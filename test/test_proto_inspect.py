# coding=utf-8
import pytest
from proto_inspect import (
    ProtoMessage,
    signed_to_uint,
    uint_to_signed,
    read_varint,
    write_varint,
    bytes_to_encode_varint,
)

# suppress 'not found' linting
pytest.raises = pytest.raises


def test_parse_empty_message():
    ProtoMessage.parse(b'')


def test_zig_zag():
    for i in range(1000):
        assert signed_to_uint(uint_to_signed(i)) == i


def test_varint_parsing():
    for i in range(1000):
        serialized = write_varint(i)
        assert len(serialized) == bytes_to_encode_varint(i)
        embedded = b'foo' + serialized + b'bar'
        assert read_varint(embedded, offset=3) == (i, len(serialized))


def test_varint_no_negatives():
    with pytest.raises(ValueError):
        write_varint(-1)
    with pytest.raises(ValueError):
        bytes_to_encode_varint(-1)


def test_truncated_varint():
    serialized = write_varint(999999999)
    assert read_varint(serialized) == (999999999, len(serialized))
    with pytest.raises(ValueError):
        read_varint(serialized[:-1])
