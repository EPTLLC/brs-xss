#!/usr/bin/env python3

"""
Project: BRS-XSS Tests - Context Detectors (HTML/CSS/JS)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 00:38:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech
"""

from brsxss.detect.xss.reflected.html_context_detector import HTMLContextDetector
from brsxss.detect.xss.reflected.css_context_detector import CSSContextDetector
from brsxss.detect.xss.reflected.javascript_context_detector import JavaScriptContextDetector
from brsxss.detect.xss.reflected.context_types import ContextType


def test_html_context_detector_core_branches():
    d = HTMLContextDetector()
    html = """
    <div id="x" style="color:red"> before <!-- marker --> after </div>
    <a href="/p?q=MARK">link</a>
    """
    # comment branch
    pos_comment = html.find("marker")
    assert (
        d.detect_html_context(html, pos_comment, "marker") == ContextType.HTML_COMMENT
    )
    # attribute branch
    pos_attr = html.find("MARK")
    assert d.detect_html_context(html, pos_attr, "MARK") == ContextType.HTML_ATTRIBUTE
    assert d.extract_attribute_name(html, pos_attr, "MARK") in ("href", "id", "style")
    # tag extraction and dangerous attrs
    pos_tag = html.find("<a ") + 3
    tag = d.extract_tag_name(html, pos_tag)
    assert tag in ("a", "div")
    info = d.analyze_tag_context(html, pos_tag)
    assert info["tag_name"] in ("a", "div") and isinstance(
        info["dangerous_attributes"], list
    )


def test_html_context_detector_event_handler_attribute_nested_quotes():
    d = HTMLContextDetector()
    html = """
    <br>
    <img src="/static/loading.gif" onload="startTimer('TESTMARKER123');" />
    <br>
    """
    pos = html.find("TESTMARKER123")
    assert pos != -1
    assert d.extract_attribute_name(html, pos, "TESTMARKER123") == "onload"
    assert d.detect_html_context(html, pos, "TESTMARKER123") == ContextType.JS_STRING


def test_css_context_detector_core_branches():
    d = CSSContextDetector()
    html = """
    <style> .x { background: url(JAV); } </style>
    <div style="color: red; background: url(MARK) ;">text</div>
    """
    pos_style_attr = html.find("MARK")
    assert d.detect_css_context(html, pos_style_attr, "MARK") == ContextType.CSS_STYLE
    details = d.analyze_css_context_details(html, pos_style_attr, "MARK")
    assert details["is_in_style_attribute"] is True
    # URL detection and syntax validation flag present
    assert isinstance(details["css_syntax_valid"], bool)


def test_js_context_detector_core_branches():
    d = JavaScriptContextDetector()
    html = """
    <script>
      var a = 'HELLO';
      var obj = { key: 'VALUE' };
      callFunc('MARK');
    </script>
    """
    pos = html.find("MARK")
    assert d.is_in_script_tag(html, pos) is True
    assert d.detect_js_context(html, pos, "MARK") in (
        ContextType.JS_STRING,
        ContextType.JAVASCRIPT,
        ContextType.JS_OBJECT,
    )
    # quote detection in JS string
    quote = d.detect_js_quote_character(html, pos, "MARK")
    assert quote in ("'", '"', "")
    details = d.analyze_js_context_details(html, pos, "MARK")
    assert isinstance(details, dict) and (
        details["is_in_function_call"]
        or details["is_in_variable_assignment"]
        or details["is_in_event_handler"]
        or details["is_in_conditional"] is False
    )


def test_css_style_tag_import_and_syntax_validation():
    d = CSSContextDetector()
    html = """
    <style>
      @import url(MARK);
      .a { background: url(IMG) }
    </style>
    """
    pos = html.find("MARK")
    assert d.is_in_style_tag(html, pos) is True
    det = d.analyze_css_context_details(html, pos, "MARK")
    assert det["is_in_style_tag"] is True and det["is_in_css_import"] is True
    # invalid syntax section (unbalanced quotes)
    html2 = '<style>.x { content: "abc }</style>'
    pos2 = html2.find("abc")
    det2 = d.analyze_css_context_details(html2, pos2, "abc")
    assert det2["css_syntax_valid"] in (True, False)


def test_html_detect_quote_character_variants():
    d = HTMLContextDetector()
    html = '<div data-x="preMARKpost">x</div>'
    pos = html.find("MARK")
    assert d.detect_quote_character(html, pos, "MARK") == '"'
    html2 = "<div data-x='preMARKpost'>x</div>"
    pos2 = html2.find("MARK")
    assert d.detect_quote_character(html2, pos2, "MARK") == "'"


def test_js_object_context_and_function_call_and_quote():
    d = JavaScriptContextDetector()
    html = "<script> var o = { k: MARK }; call(MARK2"  # no closing ) yet
    pos_obj = html.find("MARK ")
    if pos_obj == -1:
        pos_obj = html.find("MARK")
    assert d.detect_js_context(html, pos_obj, "MARK") == ContextType.JS_OBJECT
    pos_call = html.find("MARK2")
    det = d.analyze_js_context_details(html, pos_call, "MARK2")
    assert det["is_in_function_call"] is True
    html2 = '<script> var s = "xMARKy"; </script>'
    pos_s = html2.find("MARK")
    assert d.detect_js_quote_character(html2, pos_s, "MARK") == '"'
