"""Tests for parser.py, focused on CEF extension edge cases per item #2 of the review."""

import pytest

from soc_agent_toolkit.parser import parse_cef, parse_cef_extension


class TestParseCefExtension:
    def test_simple_pairs(self):
        assert parse_cef_extension("src=1.2.3.4 dst=5.6.7.8") == {"src": "1.2.3.4", "dst": "5.6.7.8"}

    def test_value_with_spaces(self):
        ext = "msg=Multiple failed SSH logins src=1.2.3.4"
        result = parse_cef_extension(ext)
        assert result["msg"] == "Multiple failed SSH logins"
        assert result["src"] == "1.2.3.4"

    def test_bare_equals_inside_value_is_not_a_new_key(self):
        # "= 5" is not "word=" immediately adjacent, so it must stay inside msg's value.
        ext = "msg=result = 5 passed src=1.2.3.4"
        result = parse_cef_extension(ext)
        assert result["msg"] == "result = 5 passed"
        assert result["src"] == "1.2.3.4"

    def test_escaped_equals_in_value(self):
        ext = r"msg=path\=C:\\temp dst=10.0.0.1"
        result = parse_cef_extension(ext)
        assert result["msg"] == "path=C:\\temp"
        assert result["dst"] == "10.0.0.1"

    def test_escaped_backslash(self):
        ext = r"filePath=C:\\Users\\admin\\file.exe"
        result = parse_cef_extension(ext)
        assert result["filePath"] == r"C:\Users\admin\file.exe"

    def test_escaped_newline(self):
        ext = r"msg=line one\nline two"
        result = parse_cef_extension(ext)
        assert result["msg"] == "line one\nline two"

    def test_empty_extension(self):
        assert parse_cef_extension("") == {}

    def test_unparseable_extension_returns_empty_dict_and_warns(self, caplog):
        result = parse_cef_extension("just some free text with no kv pairs")
        assert result == {}

    def test_multiword_style_key_with_dot(self):
        ext = "deviceCustom.field1=some value here dst=10.0.0.1"
        result = parse_cef_extension(ext)
        assert result["deviceCustom.field1"] == "some value here"
        assert result["dst"] == "10.0.0.1"


class TestParseCef:
    def test_full_cef_line(self):
        line = (
            "CEF:0|PaloAlto|NGFW|10.1|1001|Brute Force Login Attempt|8|"
            "src=203.0.113.5 dst=10.0.0.12 duser=admin msg=Multiple failed SSH logins"
        )
        alert = parse_cef(line)
        assert alert["source"] == "PaloAlto/NGFW"
        assert alert["signature"] == "1001:Brute Force Login Attempt"
        assert alert["severity"] == 8
        assert alert["src_ip"] == "203.0.113.5"
        assert alert["dest_ip"] == "10.0.0.12"
        assert alert["user"] == "admin"
        assert alert["message"] == "Multiple failed SSH logins"

    def test_cef_with_escaped_chars_in_message(self):
        line = (
            r"CEF:0|Vendor|Product|1.0|2001|Suspicious File Write|6|"
            r"src=10.0.0.5 msg=Wrote file to path\=C:\\temp\\evil.exe"
        )
        alert = parse_cef(line)
        assert alert["message"] == r"Wrote file to path=C:\temp\evil.exe"

    def test_invalid_cef_raises(self):
        with pytest.raises(ValueError):
            parse_cef("not a cef line")
