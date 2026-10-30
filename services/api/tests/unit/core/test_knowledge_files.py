import io
import zipfile

import pytest
from docx import Document
from pypdf import PdfWriter

from reconix_api.core.errors import ApiError
from reconix_api.core.knowledge_files import (
    MAX_DOCX_PARTS,
    MAX_FILE_BYTES,
    MAX_NAME,
    MAX_TEXT_CHARS,
    cut_text,
    display_name,
    kind_of,
    read_text,
)


def code_of(call) -> str:
    with pytest.raises(ApiError) as error:
        call()
    return error.value.code


def pdf_with_text(text: str) -> bytes:
    """A one-page PDF that says text, written by hand: no PDF maker is needed."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n%s\nendobj\n" % (number, body))
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1))
    out.write(b"startxref\n%d\n%%%%EOF\n" % xref)
    return out.getvalue()


def docx_with(paragraph: str, cells: list[str]) -> bytes:
    document = Document()
    document.add_paragraph(paragraph)
    table = document.add_table(rows=1, cols=len(cells))
    for cell, text in zip(table.rows[0].cells, cells, strict=True):
        cell.text = text
    out = io.BytesIO()
    document.save(out)
    return out.getvalue()


def zip_of(parts: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return out.getvalue()


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("notes.txt", "TXT"),
        ("README.MD", "MD"),
        ("api.json", "JSON"),
        ("spec.yaml", "YAML"),
        ("spec.yml", "YAML"),
        ("policy.docx", "DOCX"),
        ("scan.pdf", "PDF"),
        ("C:\\Users\\me\\scan.pdf", "PDF"),
    ],
)
def test_the_extension_picks_the_kind(name, kind):
    assert kind_of(name) == kind


@pytest.mark.parametrize("name", ["tool.exe", "script.sh", "noextension", "", "old.doc"])
def test_other_file_types_are_refused(name):
    assert code_of(lambda: kind_of(name)) == "UNSUPPORTED_FILE_TYPE"


def test_an_old_word_file_says_what_to_do():
    with pytest.raises(ApiError) as error:
        kind_of("old.doc")
    assert ".docx" in error.value.message


def test_the_display_name_has_no_folders_and_one_line():
    assert display_name("../../etc/my\n  notes.md") == "my notes.md"
    assert display_name("C:\\work\\plan.pdf") == "plan.pdf"
    assert display_name("   ") == "untitled"
    assert len(display_name("x" * 500 + ".md")) == MAX_NAME


def test_text_and_markdown_are_read_as_utf8():
    assert read_text("MD", "# Héllo\n\nworld".encode()).text == "# Héllo\n\nworld"
    assert read_text("TXT", b"\xff broken").text.endswith("broken")


def test_json_is_written_back_on_one_line():
    assert read_text("JSON", b'{"a":\n  {"b": [1, 2]}}').text == '{"a": {"b": [1, 2]}}'


def test_deep_json_does_not_grow_past_its_size():
    deep = b"[" * 900 + b"]" * 900

    assert len(read_text("JSON", deep).text) == len(deep)


@pytest.mark.parametrize(
    ("kind", "document", "secret"),
    [
        ("JSON", b'{"db": {"password": "Pa\\"ss-Secret-Tail-1234"}}', "Tail-1234"),
        ("JSON", b'{"Authorization": "ZXhhbXBsZTpzZWNyZXQ="}', "ZXhhbXBsZTpzZWNyZXQ"),
        ("JSON", b'{"cookie": "sid=abcdef123456"}', "abcdef123456"),
        # A long quoted value; joined so the commit's secret scan does not take it for one.
        ("YAML", b"password: " + b"'correct: horse battery staple word that is long end'", "horse"),
        ("YAML", b"password: correct horse battery staple", "horse"),
        ("YAML", b"secret: |\n  s3cr3t-value-on-two\n  lines-here\n", "s3cr3t"),
    ],
)
def test_secrets_in_json_and_yaml_are_masked_by_key_name(kind, document, secret):
    assert secret not in read_text(kind, document).text


def test_bad_json_is_refused():
    assert code_of(lambda: read_text("JSON", b"{not json")) == "FILE_UNREADABLE"


def test_yaml_is_read_safely():
    assert (
        read_text("YAML", b"openapi: 3.0.0\npaths: {}\n").text
        == '{"openapi": "3.0.0", "paths": {}}'
    )
    assert code_of(lambda: read_text("YAML", b"a: !!python/object:os.system {}")) == (
        "FILE_UNREADABLE"
    )


@pytest.mark.parametrize(
    "document",
    [
        b"a: &x [1, 2]\nb: *x\n",  # anchor and alias
        b"base:\n  a: 1\nother:\n  <<: {b: 2}\n",  # merge key
        b"[" * 150 + b"]" * 150,  # nested too deep
    ],
)
def test_yaml_that_can_expand_is_refused(document):
    with pytest.raises(ApiError) as error:
        read_text("YAML", document)
    assert error.value.code == "FILE_UNREADABLE"
    assert "can't be added" in error.value.message


def test_word_paragraphs_and_tables_are_read():
    text = read_text("DOCX", docx_with("Patch the VPN first.", ["host", "10.0.0.5"])).text
    assert text == "Patch the VPN first.\n\nhost | 10.0.0.5"


def test_a_word_file_with_too_many_parts_is_refused():
    parts = {f"part{n}.xml": b"x" for n in range(MAX_DOCX_PARTS + 1)}
    assert code_of(lambda: read_text("DOCX", zip_of(parts))) == "FILE_UNREADABLE"


def test_a_word_file_that_unpacks_too_large_is_refused():
    bomb = zip_of({"word/document.xml": b"0" * (51 * 1024 * 1024)})
    with pytest.raises(ApiError) as error:
        read_text("DOCX", bomb)
    assert "50 MB" in error.value.message


def test_a_broken_word_file_is_refused():
    assert code_of(lambda: read_text("DOCX", b"not a zip")) == "FILE_UNREADABLE"


def test_pdf_page_text_is_read():
    assert "Rotate the keys" in read_text("PDF", pdf_with_text("Rotate the keys")).text


def test_an_encrypted_pdf_is_refused():
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.encrypt("a-password")
    out = io.BytesIO()
    writer.write(out)
    with pytest.raises(ApiError) as error:
        read_text("PDF", out.getvalue())
    assert "encrypted" in error.value.message


def test_a_broken_pdf_is_refused():
    assert code_of(lambda: read_text("PDF", b"%PDF-1.4 nothing else")) == "FILE_UNREADABLE"


def test_a_file_over_10_mb_is_refused():
    assert code_of(lambda: read_text("TXT", b"x" * (MAX_FILE_BYTES + 1))) == "FILE_TOO_LARGE"


def test_long_text_is_cut_at_a_space_and_says_so():
    text = "word " * (MAX_TEXT_CHARS // 5 + 10)

    cut, why = cut_text(text, None)

    assert len(cut) < MAX_TEXT_CHARS
    assert cut.endswith("word")
    assert why == "TEXT_LIMIT"
    assert cut_text("short", None) == ("short", None)
    assert cut_text("x" * (MAX_TEXT_CHARS + 1), None)[0] == "x" * MAX_TEXT_CHARS


def test_reading_does_not_cut_the_text():
    assert len(read_text("TXT", b"x" * (MAX_TEXT_CHARS + 10)).text) == MAX_TEXT_CHARS + 10
