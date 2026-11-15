"""Standalone Groq chat-completion adapter for attacker-model requests."""

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from groq import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    Groq,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)


GROQ_API_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
DEFAULT_GROQ_TEMPERATURE = 0.7


class GroqProviderError(RuntimeError):
    """Base error for sanitized Groq provider failures."""


class MissingGroqAPIKeyError(GroqProviderError):
    """Raised when GROQ_API_KEY is unavailable."""


class GroqAuthenticationError(GroqProviderError):
    """Raised when Groq rejects the configured credentials."""


class GroqModelUnavailableError(GroqProviderError):
    """Raised when Groq cannot serve the requested model."""


class GroqRateLimitError(GroqProviderError):
    """Raised when Groq rate limits a request."""


class GroqTimeoutError(GroqProviderError):
    """Raised when a Groq request times out."""


class GroqNetworkError(GroqProviderError):
    """Raised when a request cannot connect to Groq."""


class GroqAPIError(GroqProviderError):
    """Raised for other Groq API failures."""


class GroqResponseError(GroqProviderError):
    """Raised when Groq returns an empty or malformed response."""


def _is_model_unavailable_error(body: Any) -> bool:
    if not isinstance(body, Mapping):
        return False
    error = body.get("error")
    if not isinstance(error, Mapping):
        return False
    code = error.get("code")
    parameter = error.get("param")
    message = error.get("message")
    model_error_codes = {
        "invalid_model",
        "model_decommissioned",
        "model_not_found",
        "model_unavailable",
    }
    if code in model_error_codes or parameter == "model":
        return True
    if isinstance(message, str):
        normalized_message = message.casefold()
        return "model" in normalized_message and any(
            phrase in normalized_message
            for phrase in (
                "not found",
                "unavailable",
                "decommissioned",
                "does not exist",
            )
        )
    return False


@dataclass(frozen=True)
class GroqProviderConfig:
    """Request settings for the standalone Groq provider."""

    model_id: str = DEFAULT_GROQ_MODEL
    temperature: float = DEFAULT_GROQ_TEMPERATURE
    timeout_seconds: float = 30.0
    max_tokens: int = 1024

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise ValueError("model_id must be a non-empty string")
        if (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, (int, float))
            or not math.isfinite(self.temperature)
            or not 0.0 <= self.temperature <= 2.0
        ):
            raise ValueError("temperature must be between 0.0 and 2.0")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if (
            not isinstance(self.max_tokens, int)
            or isinstance(self.max_tokens, bool)
            or self.max_tokens < 1
        ):
            raise ValueError("max_tokens must be a positive integer")


@dataclass(frozen=True)
class GroqProviderResponse:
    """Generated text and secret-free metadata from one provider request."""

    text: str
    metadata: dict[str, Any]


def _response_metadata(response: Any, request_timestamp: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "provider": "groq",
        "request_model": None,
        "temperature": None,
        "request_timestamp": request_timestamp,
        "response": {},
        "usage": None,
    }

    response_fields = {
        "id": "id",
        "model": "model",
        "created": "created",
        "system_fingerprint": "system_fingerprint",
    }
    response_data = {
        key: value
        for key, attribute in response_fields.items()
        if (value := getattr(response, attribute, None)) is not None
    }
    if response_data:
        metadata["response"] = response_data

    usage = getattr(response, "usage", None)
    if usage is not None:
        usage_fields = (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_tokens_details",
            "completion_tokens_details",
            "queue_time",
            "prompt_time",
            "completion_time",
            "total_time",
        )
        if isinstance(usage, Mapping):
            usage_data = {
                field: usage[field]
                for field in usage_fields
                if field in usage and usage[field] is not None
            }
        else:
            usage_data = {
                field: value
                for field in usage_fields
                if (value := getattr(usage, field, None)) is not None
            }
        metadata["usage"] = usage_data or None

    return metadata


class GroqAttackerProvider:
    """Make one explicit chat request without controlling an experiment loop."""

    def __init__(self, config: GroqProviderConfig | None = None):
        self.config = config or GroqProviderConfig()
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key or not api_key.strip():
            raise MissingGroqAPIKeyError(
                "GROQ_API_KEY is required to use the Groq provider"
            )
        self._client = Groq(
            api_key=api_key,
            base_url=GROQ_API_BASE_URL,
            timeout=self.config.timeout_seconds,
            max_retries=0,
        )

    def complete(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
    ) -> GroqProviderResponse:
        """Return one completion for the supplied prompt."""
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        if system_prompt is not None and (
            not isinstance(system_prompt, str) or not system_prompt.strip()
        ):
            raise ValueError("system_prompt must be a non-empty string when supplied")

        messages: list[dict[str, str]] = []
        if system_prompt is not None:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        request_timestamp = datetime.now(timezone.utc).isoformat()

        try:
            response = self._client.chat.completions.create(
                model=self.config.model_id,
                messages=messages,
                temperature=self.config.temperature,
                max_completion_tokens=self.config.max_tokens,
            )
        except (AuthenticationError, PermissionDeniedError):
            raise GroqAuthenticationError(
                "Groq rejected the configured credentials"
            ) from None
        except NotFoundError:
            raise GroqModelUnavailableError(
                f"Groq could not find model {self.config.model_id!r}"
            ) from None
        except RateLimitError:
            raise GroqRateLimitError("Groq rate limit exceeded") from None
        except APITimeoutError:
            raise GroqTimeoutError("Groq request timed out") from None
        except APIConnectionError:
            raise GroqNetworkError("Could not connect to Groq") from None
        except BadRequestError as exc:
            if _is_model_unavailable_error(exc.body):
                raise GroqModelUnavailableError(
                    f"Groq could not serve model {self.config.model_id!r}"
                ) from None
            raise GroqAPIError(
                f"Groq rejected the request (HTTP {exc.status_code}); "
                "check model availability and request settings"
            ) from None
        except APIStatusError as exc:
            raise GroqAPIError(
                f"Groq API request failed (HTTP {exc.status_code})"
            ) from None

        choices = getattr(response, "choices", None)
        if not isinstance(choices, (list, tuple)) or not choices:
            raise GroqResponseError("Groq returned no completion choices")
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None)
        if not isinstance(content, str) or not content.strip():
            raise GroqResponseError("Groq returned empty or malformed response text")

        metadata = _response_metadata(response, request_timestamp)
        metadata["request_model"] = self.config.model_id
        metadata["temperature"] = self.config.temperature
        return GroqProviderResponse(text=content, metadata=metadata)
