"""pcap/pcapng 파일 magic byte 검증."""

# pcap classic microsecond: d4 c3 b2 a1 (LE) / a1 b2 c3 d4 (BE)
# pcap classic nanosecond:  4d 3c b2 a1 (LE) / a1 b2 3c 4d (BE)
# pcapng Section Header Block Type: 0a 0d 0d 0a
_VALID_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)


def has_valid_pcap_magic(head: bytes) -> bool:
    """첫 4바이트가 pcap/pcapng magic 중 하나와 일치하는지 검사."""
    if not head or len(head) < 4:
        return False
    return head[:4] in _VALID_MAGICS
