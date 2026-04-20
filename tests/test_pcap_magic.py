"""pcap/pcapng magic byte 검증 테스트."""
from analyzer.core.pcap_magic import has_valid_pcap_magic


class TestHasValidPcapMagic:
    def test_pcap_microsecond_le(self):
        assert has_valid_pcap_magic(b"\xd4\xc3\xb2\xa1rest of file")

    def test_pcap_microsecond_be(self):
        assert has_valid_pcap_magic(b"\xa1\xb2\xc3\xd4rest")

    def test_pcap_nanosecond_le(self):
        assert has_valid_pcap_magic(b"\x4d\x3c\xb2\xa1rest")

    def test_pcap_nanosecond_be(self):
        assert has_valid_pcap_magic(b"\xa1\xb2\x3c\x4drest")

    def test_pcapng_shb(self):
        assert has_valid_pcap_magic(b"\x0a\x0d\x0d\x0arest")

    def test_rejects_text_file(self):
        assert not has_valid_pcap_magic(b"hello world")

    def test_rejects_empty(self):
        assert not has_valid_pcap_magic(b"")

    def test_rejects_short(self):
        assert not has_valid_pcap_magic(b"\xd4\xc3\xb2")

    def test_rejects_zip(self):
        assert not has_valid_pcap_magic(b"PK\x03\x04rest")

    def test_rejects_png(self):
        assert not has_valid_pcap_magic(b"\x89PNG\r\n\x1a\n")

    def test_rejects_none_like(self):
        assert not has_valid_pcap_magic(b"\x00\x00\x00\x00")
