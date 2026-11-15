import unittest
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from html import unescape

from tools.gmail_tool import build_email_message


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.append(dict(attrs))

    def handle_data(self, data):
        self.text.append(data)


class EmailMessageTests(unittest.TestCase):
    def build(self, **kwargs):
        return build_email_message(
            "test@example.com",
            "Test subject",
            "First line\nSecond line",
            **kwargs,
        )

    def test_email_without_link_remains_plain_text(self):
        message = self.build()

        self.assertEqual(message.get_content_type(), "text/plain")
        self.assertEqual(
            message.get_content(),
            "First line\nSecond line\n",
        )

    def test_link_is_clickable_and_exact_url_is_in_plain_fallback(self):
        url = "https://example.com/path?q=one&next=two"
        message = self.build(link_text="Open report", link_url=url)

        self.assertTrue(message.is_multipart())
        plain_part, html_part = message.iter_parts()
        self.assertEqual(
            plain_part.get_content(),
            f"First line\nSecond line\n\nOpen report: {url}\n",
        )

        parser = LinkParser()
        html_content = html_part.get_content()
        parser.feed(html_content)

        self.assertEqual(len(parser.links), 1)
        self.assertEqual(unescape(parser.links[0]["href"]), url)
        self.assertIn("Open report", "".join(parser.text))

    def test_html_sensitive_body_and_link_text_are_escaped(self):
        message = build_email_message(
            "test@example.com",
            "Test subject",
            "Body <script>alert(1)</script>",
            link_text="<img src=x onerror=alert(1)>",
            link_url="https://example.com/?a=1&b=2",
        )

        html_content = list(message.iter_parts())[1].get_content()
        self.assertIn("&lt;script&gt;", html_content)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_content)
        self.assertNotIn("<script>", html_content)
        self.assertNotIn("<img", html_content)

        # Serialized MIME remains parseable, with the supplied URL preserved
        # as the decoded href value.
        parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        parser = LinkParser()
        parser.feed(parsed.get_payload()[1].get_content())
        self.assertEqual(
            unescape(parser.links[0]["href"]),
            "https://example.com/?a=1&b=2",
        )

    def test_invalid_urls_are_rejected(self):
        for url in (
            "javascript:alert(1)",
            "https:///missing-host",
            "https://example.com:bad/",
            "https://example.com/path with spaces",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.build(link_text="Open", link_url=url)

    def test_link_fields_must_be_supplied_together(self):
        with self.assertRaises(ValueError):
            self.build(link_text="Open")
        with self.assertRaises(ValueError):
            self.build(link_url="https://example.com")


if __name__ == "__main__":
    unittest.main()
