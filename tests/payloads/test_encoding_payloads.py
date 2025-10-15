#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - payloads.encoding_payloads
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 20:18:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.payloads.encoding_payloads import EncodingPayloads


def test_encoding_payloads_collections_and_encode_helper():
    assert EncodingPayloads.get_url_encoded_payloads()
    assert EncodingPayloads.get_html_entity_payloads()
    assert EncodingPayloads.get_javascript_encoding_payloads()
    assert EncodingPayloads.get_css_encoding_payloads()
    assert EncodingPayloads.get_utf8_encoding_payloads()
    assert EncodingPayloads.get_base64_data_uri_payloads()
    assert EncodingPayloads.get_mixed_encoding_payloads()
    allp = EncodingPayloads.get_all()
    assert isinstance(allp, list) and len(allp) >= 10

    s = "<script>alert(1)</script>"
    assert EncodingPayloads.encode_payload(s, "url").startswith("%3C")
    assert "&lt;" in EncodingPayloads.encode_payload(s, "html")
    assert EncodingPayloads.encode_payload(s, "base64")
    assert EncodingPayloads.encode_payload(s, "double_url").startswith("%25")
    assert EncodingPayloads.encode_payload(s, "noop") == s


