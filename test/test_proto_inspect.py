# coding=utf-8
from proto_inspect import *


def test_parse_empty_message():
    ProtoMessage.parse(b'')
