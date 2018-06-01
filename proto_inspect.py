# coding=utf-8
from collections import Mapping, Iterable
from operator import attrgetter
from struct import pack, unpack


"""
Pure python tools for inspecting unknown protobuf data. Written for py3.6+.

Todo: Does not support the (not well publicly documented) group syntax, which isn't
really in use outside of Google.

License: MIT
"""


def uint_to_signed(n):
    """Convert a non-negative integer to the signed value with zig-zag decoding."""
    return (n >> 1) ^ (0 - (n & 1))


def signed_to_uint(n):
    """Convert a signed integer to the non-negative value with zig-zag encoding."""
    if n < 0:
        return ((n ^ -1) << 1) | 1
    else:
        return n << 1


def write_varint(value, excess_bytes=0):
    """Converts an unsigned varint to bytes."""
    def varint_bytes(n):
        while n:
            more_bytes = (n > 0x7f) or (excess_bytes > 0)
            yield (0x80 * more_bytes) | (n & 0x7f)
            n >>= 7
        if excess_bytes > 0:
            for _ in range(excess_bytes - 1):
                yield 0x80
            yield 0x00

    if value < 0:
        raise ValueError('Encoded varint must be positive')
    elif value == 0:
        return b'\0'
    else:
        return bytes(varint_bytes(value))


def read_varint(data, offset=0):
    """
    Read a varint from the given offset in the given byte data.

    Returns a tuple containing the numeric value of the varint and
    the number of bytes consumed.  (typically will be 0).
    If the varint representation does not end before the end of the data,
    a ValueError is raised.
    """
    result = 0
    bytes_read = 0
    try:
        while True:
            byte = data[offset + bytes_read]
            result |= (byte & 0x7f) << (7 * bytes_read)
            bytes_read += 1
            if byte & 0x80 == 0:
                break
    except IndexError:
        raise ValueError(f'Data truncated in varint at position {offset}')
    return result, bytes_read


def bytes_to_encode_varint(n):
    """Return the minimum number of bytes needed to represent a number in varint encoding."""
    if n < 0:
        raise ValueError('Encoded varint must be positive')
    return max(1, (n.bit_length() + 6) // 7)


def bytes_to_encode_tag(tag_id):
    """Return the minimum number of bytes needed to represent a tag with a given id."""
    return (tag_id.bit_length() + 9) // 7


class ProtoMessage(object):
    __slots__ = ('fields',)

    def __init__(self, fields=()):
        """Create a new ProtoMessage with the given iterable of protobuf Fields."""
        self.fields = list(fields)

    def __eq__(self, other):
        """Calculate equality ignoring excess varint bytes."""
        if type(other) is not type(self):
            return NotImplemented
        return other.fields == self.fields

    def __hash__(self):
        return hash((type(self), self.fields))

    def __repr__(self):
        return f'{type(self).__name__}({repr(self.fields)})'

    def __getitem__(self, field_id):
        return [field.value for field in self.fields if field.id == field_id]

    def __setitem__(self, field_id, values):
        if not isinstance(values, Iterable):
            fields_to_add = [Field(field_id, values)]
        else:
            fields_to_add = [Field(field_id, value) for value in values]
        new_fields = []
        for field in self.fields:
            # Replace the existing fields with this id at the position it's first encountered
            if field.id == field_id:
                new_fields.extend(fields_to_add)
                fields_to_add = ()
            else:
                new_fields.append(field)
        if fields_to_add:
            # If no fields with this id existed yet, add them to the end
            new_fields.extend(fields_to_add)
        self.fields = new_fields

    def __delitem__(self, field_id):
        self.fields = [field for field in self.fields if field.id != field_id]

    @classmethod
    def parse(cls, data):
        """Parse a complete ProtoMessage from a bytes-like object."""
        def get_fields():
            offset = 0
            while offset < len(data):
                field, bytes_read = Field.parse(data, offset)
                yield field
                offset += bytes_read

        return cls(get_fields())

    def byte_size(self):
        """Return the total length this message will occupy when serialized in bytes."""
        return sum(field.byte_size() for field in self.fields)

    def defaults_byte_size(self):
        """Return the total number of bytes used to serialize fields that are assigned default values."""
        return sum(field.byte_size() for field in self.fields if field.is_default())

    def strip_defaults(self):
        """
        Strip all fields from the message that are assigned default values.

        Note: This will also strip submessages, even though empty submessages may be represented intentionally.
        """
        self.fields = [field for field in self.fields if not field.is_default()]

    def total_excess_bytes(self):
        """Return the total number of excess bytes used to encode varints (tags, varint values, and lengths)."""
        return sum(field.total_excess_bytes() for field in self.fields)

    def strip_excess_bytes(self):
        """Strip all excess bytes from this message's fields and values."""
        for field in self.fields:
            field.strip_excess_bytes()

    def iter_serialize(self):
        for field in self.fields:
            yield from field.iter_serialize()

    def serialize(self):
        return b''.join(self.iter_serialize())

    def sort(self):
        """Order the fields in this message by id"""
        self.fields.sort(key=attrgetter('id'))

    def pack_repeated(self, field_ids_to_pack):
        if not isinstance(field_ids_to_pack, Iterable):
            ids_to_pack = (field_ids_to_pack,)
        else:
            ids_to_pack = set(field_ids_to_pack)

        def new_fields():
            def build_packed(values):
                for value in values:
                    yield from value.iter_serialize()

            values_to_pack = {}
            for field in self.fields:
                if field.id in ids_to_pack:
                    if field.id not in values_to_pack:
                        values_to_pack[field.id] = [field.value]
                    else:
                        current_type = type(values_to_pack[field.id][0])
                        if type(field.value) is not current_type:
                            raise ValueError(
                                f'Fields with id {field.id} have heterogenous types and cannot be packed '
                                f'together: found {current_type.__name__} and {type(field.value).__name__}'
                            )
                        values_to_pack[field.id].append(field.value)
            for field in self.fields:
                if field.id in ids_to_pack:
                    if field.id in values_to_pack:
                        # Only the first time we encounter an original field, emit the packed field
                        yield Field(field.id, Blob(b''.join(build_packed(values_to_pack.pop(field.id)))))
                else:
                    yield field

        return ProtoMessage(new_fields())

    def unpack_repeated(self, fields_with_value_klass_dict):
        def new_fields():
            for field in self.fields:
                unpack_klass = fields_with_value_klass_dict.get(field.id)
                if unpack_klass:
                    if type(field.value) is not Blob:
                        raise TypeError(
                            f'Field id {field.id} exists with non-Blob '
                            f'type {type(field.value).__name__}, cannot unpack'
                        )
                    for unpacked_value in unpack_klass.parse_repeated(field.value.value):
                        yield Field(field.id, unpacked_value)
                else:
                    yield field  # yield original field unchanged

        return ProtoMessage(new_fields())

    def as_map_item(
        self,
        key_klass=None, key_interpretation='value',
        value_klass=None, value_interpretation='value',
        fail_on_extra_fields=False,
    ):
        key_fields = self[1]
        if len(key_fields) > 1:
            raise ValueError('Map item has multiple fields with map "key" id 1')
        value_fields = self[2]
        if len(value_fields) > 1:
            raise ValueError('Map item has multiple fields with map "value" id 2')
        if fail_on_extra_fields and len(self.fields) > len(key_fields) + len(value_fields):
            raise ValueError('Map item has extra fields')
        key = key_fields[0] if key_fields else (key_klass() if key_klass else None)
        value = value_fields[0] if value_fields else (value_klass() if value_klass else None)
        if key_klass is None:
            map_key = key
        else:
            if not isinstance(key, key_klass):
                raise ValueError(
                    f'Map key is of the wrong type: '
                    f'got {type(key).__name__}, expected {key_klass.__name__}'
                )
            try:
                map_key = getattr(key, key_interpretation)
            except AttributeError:
                raise TypeError(
                    f'Invalid interpretation {repr(key_interpretation)} for key klass {key_klass.__name__}'
                )
        if value_klass is None:
            map_value = value
        else:
            if not isinstance(value, value_klass):
                raise ValueError(
                    f'Map value is of the wrong type: '
                    f'got {type(value).__name__}, expected {value_klass.__name__}'
                )
            try:
                map_value = getattr(value, value_interpretation)
            except AttributeError:
                raise TypeError(
                    f'Invalid interpretation {repr(value_interpretation)} for value klass {value_klass.__name__}'
                )
        return map_key, map_value


class Field(object):
    __slots__ = ('id', 'value', 'excess_tag_bytes',)

    def __init__(self, id_, value, excess_tag_bytes=0):
        self.id = id_
        self.value = value
        self.excess_tag_bytes = excess_tag_bytes

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.id == self.id and other.value == self.value

    def __hash__(self):
        return hash((type(self), self.id, self.value))

    def __repr__(self):
        if self.excess_tag_bytes:
            return (
                f'{type(self).__name__}('
                f'{repr(self.id)}, '
                f'{repr(self.value)}, '
                f'excess_tag_bytes={repr(self.excess_tag_bytes)}'
                f')'
            )
        else:
            return (
                f'{type(self).__name__}('
                f'{repr(self.id)}, '
                f'{repr(self.value)}'
                f')'
            )

    @classmethod
    def parse(cls, data, offset=0):
        tag, tag_bytes = read_varint(data, offset)
        excess_tag_bytes = tag_bytes - bytes_to_encode_varint(tag)
        id_ = tag >> 3
        wire_type = tag & 7
        value_klass = VALUE_TYPES.get(wire_type)
        if not value_klass:
            raise ValueError(f'Invalid or unsupported field wire type {wire_type} in tag at position {offset}')
        value, value_bytes = value_klass.parse(data, offset + tag_bytes)
        return cls(id_, value, excess_tag_bytes), tag_bytes + value_bytes

    def is_default(self):
        return self.value.value == self.value.default_value

    def total_excess_bytes(self):
        return self.excess_tag_bytes + self.value.total_excess_bytes()

    def strip_excess_bytes(self):
        self.excess_tag_bytes = 0
        self.value.strip_excess_bytes()

    def byte_size(self):
        return bytes_to_encode_tag(self.id) + self.excess_tag_bytes + self.value.byte_size()

    def iter_serialize(self):
        yield write_varint((self.id << 3) | self.value.wire_type, self.excess_tag_bytes)
        yield from self.value.iter_serialize()

    def serialize(self):
        return b''.join(self.iter_serialize())


class ProtoValue(object):
    __slots__ = ('value',)

    def __init__(self, value=None):
        if value is None:
            self.value = self.default_value
        else:
            self.value = value

    def __repr__(self):
        excess_bytes = getattr(self, 'excess_bytes', None)
        if excess_bytes:
            return f'{type(self).__name__}({repr(self.value)}, excess_bytes={excess_bytes})'
        else:
            return f'{type(self).__name__}({repr(self.value)})'

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.value == self.value

    def __hash__(self):
        return hash((type(self), self.value))

    @classmethod
    def parse(cls, data, offset=0):
        raise NotImplementedError

    @classmethod
    def parse_repeated(cls, data):
        offset = 0
        while offset < len(data):
            value, bytes_read = cls.parse(data, offset)
            yield value
            offset += bytes_read

    @property
    def default_value(self):
        raise NotImplementedError

    @property
    def wire_type(self):
        raise NotImplementedError

    def byte_size(self):
        raise NotImplementedError

    def total_excess_bytes(self):
        raise NotImplementedError

    def strip_excess_bytes(self):
        raise NotImplementedError

    def iter_serialize(self):
        raise NotImplementedError

    def serialize(self):
        return b''.join(self.iter_serialize())


class Varint(ProtoValue):
    __slots__ = ('excess_bytes',)
    wire_type = 0
    default_value = 0

    def __init__(self, value=None, excess_bytes=0):
        super().__init__(value)
        self.excess_bytes = excess_bytes

    @classmethod
    def parse(cls, data, offset=0):
        value, value_bytes = read_varint(data, offset)
        excess_bytes = value_bytes - bytes_to_encode_varint(value)
        return cls(value, excess_bytes), value_bytes

    def byte_size(self):
        return bytes_to_encode_varint(self.value) + self.excess_bytes

    def total_excess_bytes(self):
        return self.excess_bytes

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(self.value, self.excess_bytes)

    @property
    def unsigned(self):
        return self.value

    @unsigned.setter
    def unsigned(self, value):
        self.value = value

    @property
    def signed(self):
        return uint_to_signed(self.value)

    @signed.setter
    def signed(self, value):
        self.value = signed_to_uint(value)

    @property
    def boolean(self):
        return bool(self.value)

    @boolean.setter
    def boolean(self, value):
        self.value = int(bool(value))

    @property
    def uint32(self):
        if self.value not in range(0x1_0000_0000):
            raise ValueError('Varint out of range for uint32')
        return self.value

    @uint32.setter
    def uint32(self, value):
        if value not in range(0x1_0000_0000):
            raise ValueError('Value out of range for uint32')
        self.value = value

    @property
    def int32(self):
        if self.value not in range(0x1_0000_0000):
            raise ValueError('Varint out of range for int32')
        if self.value & 0x8000_0000:
            return self.value - 0x1_0000_0000
        else:
            return self.value

    @int32.setter
    def int32(self, value):
        if value not in range(-0x8000_0000, 0x8000_0000):
            raise ValueError('Value out of range for int32')
        self.value = value & 0xffff_ffff

    @property
    def sint32(self):
        if self.value not in range(0x1_0000_0000):
            raise ValueError('Varint out of range for sint32')
        return uint_to_signed(self.value)

    @sint32.setter
    def sint32(self, value):
        if value not in range(-0x8000_0000, 0x8000_0000):
            raise ValueError('Value out of range for sint32')
        self.value = signed_to_uint(value)

    @property
    def uint64(self):
        if self.value not in range(0x1_0000_0000_0000_0000):
            raise ValueError('Varint out of range for uint64')
        return self.value

    @uint64.setter
    def uint64(self, value):
        if value not in range(0x1_0000_0000_0000_0000):
            raise ValueError('Value out of range for uint64')
        self.value = value

    @property
    def int64(self):
        if self.value not in range(0x1_0000_0000_0000_0000):
            raise ValueError('Varint out of range for int64')
        if self.value & 0x8000_0000_0000_0000:
            return self.value - 0x1_0000_0000_0000_0000
        else:
            return self.value

    @int64.setter
    def int64(self, value):
        if value not in range(-0x8000_0000_0000_0000, 0x8000_0000_0000_0000):
            raise ValueError('Value out of range for int64')
        self.value = value & 0xffff_ffff_ffff_ffff

    @property
    def sint64(self):
        if self.value not in range(0x1_0000_0000_0000_0000):
            raise ValueError('Varint out of range for sint64')
        return uint_to_signed(self.value)

    @sint64.setter
    def sint64(self, value):
        if value not in range(-0x8000_0000_0000_0000, 0x8000_0000_0000_0000):
            raise ValueError('Value out of range for sint64')
        self.value = signed_to_uint(value)


class Blob(ProtoValue):
    __slots__ = ('excess_bytes',)
    wire_type = 2
    default_value = b''

    def __init__(self, value=None, excess_bytes=0):
        super().__init__(value)
        self.excess_bytes = excess_bytes

    @classmethod
    def parse(cls, data, offset=0):
        length, length_bytes = read_varint(data, offset)
        excess_bytes = length_bytes - bytes_to_encode_varint(length)
        start = offset + length_bytes
        value = data[start:start + length]
        if len(value) < length:
            raise ValueError(f'Data truncated in length-delimited data beginning at position {start}')
        return cls(value, excess_bytes), length_bytes + length

    @classmethod
    def for_repeated(cls, *args, **kwargs):
        val = cls()
        val.set_as_repeated(*args, **kwargs)
        return val

    @classmethod
    def for_map(cls, *args, **kwargs):
        val = cls()
        val.set_as_map(*args, **kwargs)

    def byte_size(self):
        length = len(self.value)
        return bytes_to_encode_varint(length) + self.excess_bytes + length

    def total_excess_bytes(self):
        return self.excess_bytes

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(len(self.value), self.excess_bytes)
        yield self.value

    @property
    def text(self):
        return self.value.decode('utf-8')

    @text.setter
    def text(self, value):
        self.value = value.encode('utf-8')

    @property
    def message(self):
        return ProtoMessage.parse(self.value)

    @message.setter
    def message(self, value):
        self.value = value.serialize()

    def get_as_repeated(self, value_klass, interpretation):
        try:
            return [
                getattr(value, interpretation)
                for value in value_klass.parse_repeated(self.value)
            ]
        except AttributeError:
            raise TypeError(f'Invalid interpretation {repr(interpretation)} for value klass {value_klass.__name__}')

    def set_as_repeated(self, values, value_klass=None, interpretation='value'):
        def emitter():
            if value_klass is None:
                for value in values:
                    yield from value.iter_serialize()
            else:
                value_writer = value_klass()
                if not hasattr(value_writer, interpretation):
                    raise TypeError(
                        f'Invalid interpretation {repr(interpretation)} for value klass {value_klass.__name__}'
                    )
                for value in values:
                    setattr(value_writer, interpretation, value)
                    yield from value_writer.iter_serialize()

        self.value = b''.join(emitter())

    def get_as_repeated_with_excess_bytes(self, value_klass, interpretation='value'):
        try:
            return [
                (getattr(value, interpretation), value.total_excess_bytes())
                for value in value_klass.parse_repeated(self.value)
            ]
        except AttributeError:
            raise TypeError(
                f'Invalid interpretation {repr(interpretation)} for value klass {value_klass.__name__}'
            )

    def set_as_repeated_with_excess_bytes(self, values_with_excess_bytes, value_klass, interpretation):
        def emitter():
            value_writer = value_klass()
            if not hasattr(value_writer, interpretation):
                raise TypeError(
                    f'Invalid interpretation {repr(interpretation)} for value klass {value_klass.__name__}'
                )
            if not hasattr(value_writer, 'excess_bytes'):
                raise TypeError(
                    f'Value klass {value_klass.__name__} cannot have excess bytes'
                )
            for (value, excess_bytes) in values_with_excess_bytes:
                setattr(value_writer, interpretation, value)
                value_writer.total_excess_bytes = excess_bytes
                yield from value_writer.iter_serialize()

        self.value = b''.join(emitter())

    def get_as_map(self, *args, **kwargs):
        return [
            item_msg.as_map_item(*args, **kwargs)
            for item_msg in self.get_as_repeated(Blob, 'message')
        ]

    def set_as_map(
        self,
        mapping,
        key_klass=None, key_interpretation='value',
        value_klass=None, value_interpretation='value',
    ):
        if isinstance(mapping, Mapping):
            items = mapping.items()
        else:
            items = mapping

        def build_result():
            key_writer = key_klass() if key_klass is not None else None
            value_writer = value_klass() if value_klass is not None else None
            key_field = Field(1, key_writer)
            value_field = Field(2, value_writer)
            item_msg = ProtoMessage((key_field, value_field))
            for key, value in items:
                if key_klass is None:
                    key_field.value = key
                else:
                    try:
                        setattr(key_writer, key_interpretation, key)
                    except AttributeError:
                        raise TypeError(
                            f'Invalid interpretation {repr(key_interpretation)} '
                            f'for key klass {key_klass.__name__}'
                        )
                if value_klass is None:
                    value_field.value = value
                else:
                    try:
                        setattr(value_writer, value_interpretation, value)
                    except AttributeError:
                        raise TypeError(
                            f'Invalid interpretation {repr(value_interpretation)} '
                            f'for value klass {value_klass.__name__}'
                        )
                yield item_msg

        self.set_as_repeated(build_result(), Blob, 'message')


class Fixed32(ProtoValue):
    __slots__ = ()
    wire_type = 5
    default_value = b'\0' * 4

    @classmethod
    def parse(cls, data, offset=0):
        value = data[offset:offset + 4]
        if len(value) < 4:
            raise ValueError(f'Data truncated in fixed32 value beginning at position {offset}')
        return cls(value), 4

    def byte_size(self):
        return 4

    def total_excess_bytes(self):
        return 0

    def strip_excess_bytes(self):
        pass

    def iter_serialize(self):
        yield self.value

    @property
    def float4(self):
        result, = unpack('<f', self.value)
        return result

    @float4.setter
    def float4(self, value):
        self.value = pack('<f', value)

    single = float4

    @property
    def fixed32(self):
        result, = unpack('<L', self.value)
        return result

    @fixed32.setter
    def fixed32(self, value):
        self.value = pack('<L', value)

    @property
    def sfixed32(self):
        result, = unpack('<l', self.value)
        return result

    @sfixed32.setter
    def sfixed32(self, value):
        self.value = pack('<l', value)


class Fixed64(ProtoValue):
    __slots__ = ()
    wire_type = 1
    default_value = b'\0' * 8

    @classmethod
    def parse(cls, data, offset=0):
        value = data[offset:offset + 8]
        if len(value) < 8:
            raise ValueError(f'Data truncated in fixed64 value beginning at position {offset}')
        return cls(value), 8

    def byte_size(self):
        return 8

    def total_excess_bytes(self):
        return 0

    def strip_excess_bytes(self):
        pass

    def iter_serialize(self):
        yield self.value

    @property
    def float8(self):
        result, = unpack('<d', self.value)
        return result

    @float8.setter
    def float8(self, value):
        self.value = pack('<d', value)

    double = float8

    @property
    def fixed64(self):
        result, = unpack('<Q', self.value)
        return result

    @fixed64.setter
    def fixed64(self, value):
        self.value = pack('<Q', value)

    @property
    def sfixed64(self):
        result, = unpack('<q', self.value)
        return result

    @sfixed64.setter
    def sfixed64(self, value):
        self.value = pack('<q', value)


VALUE_TYPES = {
    klass.wire_type: klass
    for klass in [
        Varint,
        Blob,
        Fixed32,
        Fixed64,
    ]
}
