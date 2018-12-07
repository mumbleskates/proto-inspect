# coding=utf-8
from collections.abc import Mapping, Iterable
from operator import attrgetter
from struct import pack, unpack


__doc__ = """
Pure python tools for inspecting unknown protobuf data. Written for py3.6+.

Author: Kent Ross
License: MIT

To parse a proto, pass a bytes-like object to ProtoMessage.parse(), with an
optional offset. This returns a ProtoMessage object with a fields attribute
that contains all the fields of the message in the exact order they appeared.

No assumptions are made about the actual schema of the message. Protobufs are
fully parseable without knowledge of the meaning of their contents, and that's
where this library comes in: allowing you to deserialize, inspect, modify, and
re-serialize proto values, fields, and messages at will with various partially-
and non-supported variations.


Parsing methods:

Whole messages can be parsed via ProtoMessage.parse(), which attempts to consume
the entire bytes-like object passed to it.

The method parse_field(data, offset=0) parses a single field or group from the
given data and offset, returning a 2-tuple of the resulting object and the
number of bytes consumed.

Field.parse(...) and Group.parse(...) are not useful for typical consumption;
use parse_field() instead.

Value type .parse(data, offset=0): Likewise to parse_field, returns a 2-tuple
of the parsed value and the number of bytes consumed from the given data and
offset.


Every message, field, value, and group has some variation of the following APIs:

    * operators ==, hash()
        Note: These objects are mutable, and hash() is not safe if you plan to
        change their values.

    * byte_size()
        Returns the exact number of bytes when serialized as an int.

    * total_excess_bytes()
        Returns the number of bytes the message would be shortened by if all
        extraneous varint bytes are removed as an int.

        Most protobuf varints have multiple valid representations because they
        are little-endian and trailing zeros are still interpreted as valid.
        Varints are used extensively: for tags, many integer value types, and
        the byte length of blob values. One of the unique features of this lib
        is that any proto value it manages to parse, it should re-serialize with
        the EXACT bytes it originated from, including extra bytes in varints.
        (It is not designed to be performant; if you need to strip these bytes,
        you should probably use the official protobuf libraries to de-and-re-
        serialize the message.)

    * strip_excess_bytes()
        Recursively removes all excess varint bytes from this value, field,
        group, or message.

    * serialize()
        Serializes the value, field, group, or message and returns it as a bytes
        object.

    * iter_serialize()
        Returns constituent chunks of the serialization as a generator. Used
        internally by serialize().


APIs unique to values (Varint, Blob, Fixed32, Fixed64):

    * excess_bytes
        If a value contains a varint, it will have this attribute. It can be set
        to arbitrary non-negative integers; however, values that result in a
        serialized varint length of over 10 bytes may not be valid or readable
        at all by other proto parsing libraries.

    * parse(data, offset=0)
        Returns an instance of the value read from the given data and offset,
        and the number of bytes consumed (as a 2-tuple).

    * parse_repeated(data, offset=0)
        Returns a generator that repeatedly consumes from the given data and
        offset, returning only the data each time. Terminates when it reads to
        the end of the data cleanly. Used for reading the values from e.g.
        packed repeated fields, which are stored with variable-length (Blob)
        wire type and contain only the values concatenated together, omitting
        the tags.

    Typed access properties:
        Provides get/set views of the values translated for the given
        representation:

        Varint:
            unsigned, signed, boolean,
            uint32, int32, sint32,
            uint64, int64, sint64
            value: un-translated int value

        Fixed32:
            float4 (alias single), fixed32, sfixed32
            value: 4-character bytes object

        Fixed64:
            float8 (alias double), fixed64, sfixed64
            value: 8-character bytes object

        Blob:
            text (utf-8), message (nested protobuf message)
            value: plain bytes object

    Blobs also have methods for getting and setting as repeated values of
    specified types and interpretations, and for translating to and from packed
    standard maps (maps are implemented as repeated message types with key as
    field 1 and value as field 2).


APIs unique to fields:
    * is_default()
        Returns a boolean value, true if this value is its proto3 default.


APIs common to fields, messages, and groups:
    * autoparse_recursive()
        Recursively parse Blob values if they look like valid messages.

APIs unique to messages and groups:
    * Access by index
        Accessing by index yields the field or fields with that id in the order
        they appear in the message (`msg[1]`). If there is only one, it is
        returned without wrapping in a list for convenience. If you always
        need a list, use the value_list(field_id) function instead.

    * Setting by index
        Likewise, iterables of values and groups can be assigned to existing or
        new field ids through setting by index (`msg[1] = Varint(2)`),
        overwriting any existing fields.

    * pack_repeated(field_ids_to_pack)
        Converts all fields with ids from the given iterable or scalar int to
        packed-repeated format.

    * unpack_repeated(fields_with_value_klass_dict)
        Performs the reverse operation of pack_repeated. The argument given is
        a dict mapping from field id to the type of value packed (Varint, Blob,
        etc.)

    * field_as_map(field_id, ...)
        Convenience method that returns an iterable of the given field as if it
        were a repeated map item.

    * defaults_byte_size()
        Returns the total byte size of serialized values that could be omitted
        as defaults in proto3.

        Proto3 fields are typically not serialized at all when they manifest
        their default values, which are always the zero representation. Proto2
        differs from this in that defaults may not be zero and the presence or
        absence of a default- or zero-valued field conveys additional value by
        (controversial, deprecated) design.

    * strip_defaults()
        Removes all default-valued fields from the message or group (non-
        recursively: does not propagate to lower groups).

        Note that this will also remove zero values from e.g. repeated fields,
        zero-length serialized sub-message fields, and other values that are
        still serialized in proto3 even when they are default; exercise caution.
"""


NoneType = type(None)


def uint_to_signed(n):
    """
    Convert a non-negative integer to the signed value with zig-zag decoding.
    """
    return (n >> 1) ^ (0 - (n & 1))


def signed_to_uint(n):
    """
    Convert a signed integer to the non-negative value with zig-zag encoding.
    """
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
    the number of bytes consumed.

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
    """
    Return the minimum number of bytes needed to represent a number in varint
    encoding.
    """
    if n < 0:
        raise ValueError('Encoded varint must be positive')
    return max(1, (n.bit_length() + 6) // 7)


def bytes_to_encode_tag(tag_id):
    """
    Return the minimum number of bytes needed to represent a tag with a given
    id.
    """
    return (tag_id.bit_length() + 9) // 7


def _recursive_autoparse(fields, parse_empty):
    """
    Auto-parses a field into submessages recursively, returning the number
    of submessages successfully parsed.
    """
    num_parsed = 0
    for field in fields:
        try:
            if field.parse_submessage(parse_empty):
                num_parsed += 1 + _recursive_autoparse(
                    field.value.fields,
                    parse_empty
                )
        except ValueError:
            pass
    return num_parsed


class _Serializable(object):
    __slots__ = ()

    def _iter_pretty(self, indent, depth):
        raise NotImplementedError

    def pretty(self, indent=4):
        return ''.join(self._iter_pretty(' ' * indent, 0))

    def byte_size(self):
        raise NotImplementedError

    def total_excess_bytes(self):
        return 0

    def strip_excess_bytes(self):
        pass

    def iter_serialize(self):
        raise NotImplementedError

    def serialize(self):
        return b''.join(self.iter_serialize())


class _FieldSet(_Serializable):
    __slots__ = ('fields',)

    def __init__(self, fields):
        if not isinstance(fields, Iterable):
            raise TypeError(f'Cannot create fieldset with non-iterable type '
                            f'{repr(type(fields).__name__)}')
        self.fields = list(fields)

    def __eq__(self, other):
        """Calculate equality ignoring excess varint bytes."""
        if type(other) is not type(self):
            return NotImplemented
        return other.fields == self.fields

    def __hash__(self):
        return hash((type(self), self.fields))

    def __iter__(self):
        return iter(self.fields)

    def __repr__(self):
        return (
            f'{type(self).__name__}('
            f'{repr(self.fields)}'
            f')'
        )

    def _iter_pretty(self, indent, depth):
        if self.fields:
            yield f'{type(self).__name__}('
            yield from self._pretty_extra_pre()
            yield '[\n'
            for field in self:
                yield indent * (depth + 1)
                yield from field._iter_pretty(indent, depth + 1)
                yield ',\n'
            yield f'{indent * depth}]'
            yield from self._pretty_extra_post()
            yield ')'
        else:
            yield repr(self)

    def _pretty_extra_pre(self):
        return ()

    def _pretty_extra_post(self):
        return ()

    def __getitem__(self, field_id):
        result = self.value_list(field_id)
        if not len(result):
            raise KeyError(f'Field not found: {repr(field_id)}')
        if len(result) == 1:
            return result[0]
        else:
            return result

    def value_list(self, field_id):
        return [field.value for field in self if field.id == field_id]

    def __setitem__(self, field_id, values):
        def to_field(value):
            """Wrap the value in a field only if it isn't a group."""
            if isinstance(value, Group):
                return Group(
                    field_id,
                    list(value.fields),
                    value.excess_tag_bytes,
                    value.excess_end_tag_bytes
                )
            else:
                return Field(field_id, value)

        if not isinstance(values, Iterable):
            fields_to_add = [to_field(values)]
        else:
            fields_to_add = [to_field(value) for value in values]
        new_fields = []
        for field in self:
            # Replace the existing fields with this id at the position it's
            # first encountered
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
        self.fields = [field for field in self if field.id != field_id]

    def field_as_map(self, field_id, *args, **kwargs):
        """
        Return a generator of (key, value) pairs for the given unpacked repeated
        map item field id in this message.

        Extra arguments are the same as those for "as_map_item", applied to each
        value in the given field id. All values under the specified field id
        must be of type Blob, and will be parsed as messages.

        Example: dict(m.field_as_map(5, Blob, 'text', Varint, 'signed'))
        """
        values = self.value_list(field_id)
        if all(isinstance(val, (Blob, SubMessage)) for val in values):
            return (
                val.message.as_map_item(*args, **kwargs)
                for val in self.value_list(field_id)
            )
        else:
            raise ValueError('Non-Blob values found at the specified field id')

    def sort(self):
        """Order the fields in this message by id"""
        self.fields.sort(key=attrgetter('id'))

    def parse_submessages(
        self,
        field_ids=(),
        auto=False,
        auto_parse_empty=False
    ):
        """
        Parse Blob values in the given field ids into messages and return the
        number of values parsed thus. If every parse is successful, replaces the
        fields with the parsed version.

        If auto is set to True, blob values in field ids that are NOT specified
        will also be converted to SubMessage type if and only if they appear to
        be valid protobuf messages. In this case, field ids that ARE specified
        are interpreted as required, and if any are not valid an error will
        be raised.
        """
        if not isinstance(field_ids, Iterable):
            field_ids = (field_ids,)
        num_parsed = 0
        new_fields = []
        for field in self:
            if field.id in field_ids:
                if not isinstance(field.value, (Blob, SubMessage)):
                    raise ValueError(
                        f'Encountered field at specified id {field.id} with '
                        f'non-Blob type {type(field.value).__name__}'
                    )
                if isinstance(field.value, Blob):
                    new_fields.append(Field(
                        field.id,
                        SubMessage(
                            field.value.message,
                            excess_bytes=field.value.excess_bytes
                        ),
                        excess_tag_bytes=field.excess_tag_bytes
                    ))
                    num_parsed += 1
                else:
                    new_fields.append(field)
            elif auto:
                if (
                        isinstance(field.value, Blob) and
                        (len(field.value.value) > 0 or auto_parse_empty)
                ):
                    try:
                        new_fields.append(Field(
                            field.id,
                            SubMessage(
                                field.value.message,
                                excess_bytes=field.value.excess_bytes
                            ),
                            excess_tag_bytes=field.excess_tag_bytes
                        ))
                        num_parsed += 1
                    except ValueError:
                        new_fields.append(field)
                else:
                    new_fields.append(field)

        self.fields = new_fields
        return num_parsed

    def autoparse_recursive(self, parse_empty=False):
        """
        Recursively parse submessages whenever possible, returning the total
        number of submessages parsed thusly.
        """
        return _recursive_autoparse(self.fields, parse_empty)

    def unparse_submessages(self, field_ids=None):
        """
        Replace SubMessage fields at the specified ids with their serialized
        Blob values.

        If field_ids is None, performs this action on all submessages.
        """
        if field_ids is not None and not isinstance(field_ids, Iterable):
            field_ids = (field_ids,)
        num_unparsed = 0
        new_fields = []
        for field in self:
            if isinstance(field.value, SubMessage):
                if field_ids is None or field.id in field_ids:
                    new_fields.append(Field(
                        field.id,
                        Blob(
                            field.value.bytes,
                            excess_bytes=field.value.excess_bytes
                        ),
                        excess_tag_bytes=field.excess_tag_bytes
                    ))
                    num_unparsed += 1
                else:
                    new_fields.append(field)
            else:
                new_fields.append(field)

        self.fields = new_fields
        return num_unparsed

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
            for field in self:
                if field.id in ids_to_pack:
                    if field.id not in values_to_pack:
                        values_to_pack[field.id] = [field.value]
                    else:
                        current_type = type(values_to_pack[field.id][0])
                        if type(field.value) is not current_type:
                            raise ValueError(
                                f'Fields with id {field.id} have heterogenous '
                                f'types and cannot be packed together: found '
                                f'{current_type.__name__} and '
                                f'{type(field.value).__name__}'
                            )
                        values_to_pack[field.id].append(field.value)
            for field in self:
                if field.id in ids_to_pack:
                    if field.id in values_to_pack:
                        # Only the first time we encounter an original field,
                        # emit the packed field
                        yield Field(
                            field.id,
                            Blob(b''.join(
                                build_packed(values_to_pack.pop(field.id))
                            ))
                        )
                else:
                    yield field

        return ProtoMessage(new_fields())

    def unpack_repeated(self, fields_with_value_klass_dict):
        def new_fields():
            for field in self:
                unpack_klass = fields_with_value_klass_dict.get(field.id)
                if unpack_klass:
                    if type(field.value) is not Blob:
                        raise TypeError(
                            f'Field id {field.id} exists with non-Blob '
                            f'type {type(field.value).__name__}, cannot unpack'
                        )
                    for val in unpack_klass.parse_repeated(field.value.value):
                        yield Field(field.id, val)
                else:
                    yield field  # yield original field unchanged

        return ProtoMessage(new_fields())

    def byte_size(self):
        """
        Return the total length this message will occupy when serialized in
        bytes.
        """
        return sum(field.byte_size() for field in self)

    def defaults_byte_size(self):
        """
        Return the total number of bytes used to serialize fields that are
        assigned default values.
        """
        return sum(
            field.byte_size()
            for field in self
            if field.is_default()
        )

    def strip_defaults(self):
        """
        Strip all fields from the message that are assigned default values,
        returning the number of fields so removed.

        Note: This will also strip submessages, even though empty submessages
        may be represented intentionally.
        """
        old_len = len(self.fields)
        self.fields = [field for field in self if not field.is_default()]
        return old_len - len(self.fields)

    def total_excess_bytes(self):
        """
        Return the total number of excess bytes used to encode varints (tags,
        varint values, and lengths).
        """
        return sum(field.total_excess_bytes() for field in self)

    def strip_excess_bytes(self):
        """Strip all excess bytes from this message's fields and values."""
        for field in self:
            field.strip_excess_bytes()

    def iter_serialize(self):
        for field in self:
            yield from field.iter_serialize()


class ProtoMessage(_FieldSet):
    __slots__ = ()

    def __init__(self, fields=()):
        """
        Create a new ProtoMessage with the given iterable of protobuf Fields.
        """
        super().__init__(fields)

    def __repr__(self):
        return f'{type(self).__name__}({repr(self.fields)})'

    @classmethod
    def parse(cls, data, allow_orphan_group_ends=False):
        """Parse a complete ProtoMessage from a bytes-like object."""
        def get_fields():
            offset = 0
            while offset < len(data):
                field, bytes_read = parse_field(data, offset)
                if (
                    isinstance(field.value, GroupEnd) and
                    not allow_orphan_group_ends
                ):
                    raise ValueError(f'Orphaned group end with id {field.id} '
                                     f'at position {offset}')
                yield field
                offset += bytes_read

        return cls(get_fields())

    @property
    def message(self):
        return self

    def as_map_item(
        self,
        key_klass=NoneType, key_interpretation='value',
        value_klass=NoneType, value_interpretation='value',
        fail_on_extra_fields=True,
        fail_on_submessage_type=False,
    ):
        key_fields = self[1]
        if isinstance(key_fields, list):
            raise ValueError('Map item has multiple fields with map "key" id 1')
        value_fields = self[2]
        if isinstance(value_fields, list):
            raise ValueError(
                'Map item has multiple fields with map "value" id 2'
            )
        if (
            fail_on_extra_fields
            and len(self.fields) > 2
        ):
            raise ValueError('Map item has extra fields')
        key = key_fields if key_fields else key_klass()
        value = value_fields if value_fields else value_klass()
        if key_klass is NoneType:
            map_key = key
        else:
            if not isinstance(key, key_klass):
                if key_klass is Blob and isinstance(key, SubMessage):
                    if fail_on_submessage_type:
                        raise ValueError('Blob expected but SubMessage found')
                else:
                    raise ValueError(
                        f'Map key is of the wrong type: got '
                        f'{type(key).__name__}, expected {key_klass.__name__}'
                    )
            try:
                map_key = getattr(key, key_interpretation)
            except AttributeError:
                raise TypeError(
                    f'Invalid interpretation {repr(key_interpretation)} for '
                    f'key klass {key_klass.__name__}'
                )
        if value_klass is NoneType:
            map_value = value
        else:
            if not isinstance(value, value_klass):
                if value_klass is Blob and isinstance(value, SubMessage):
                    if fail_on_submessage_type:
                        raise ValueError('Blob expected but SubMessage found')
                else:
                    raise ValueError(
                        f'Map value is of the wrong type: got '
                        f'{type(value).__name__}, expected '
                        f'{value_klass.__name__}'
                    )
            try:
                map_value = getattr(value, value_interpretation)
            except AttributeError:
                raise TypeError(
                    f'Invalid interpretation {repr(value_interpretation)} for '
                    f'value klass {value_klass.__name__}'
                )
        return map_key, map_value


def parse_field(data, offset=0):
    tag, tag_bytes = read_varint(data, offset)
    field_id = tag >> 3
    wire_type = tag & 7
    excess_tag_bytes = tag_bytes - bytes_to_encode_tag(field_id)
    value_klass = VALUE_TYPES.get(wire_type)
    if not value_klass:
        raise ValueError(f'Invalid or unsupported field wire type '
                         f'{wire_type} in tag at position {offset}')
    field, field_bytes = FIELD_TYPES.get(wire_type, Field).parse(
        field_id, wire_type, excess_tag_bytes,
        data,
        offset + tag_bytes
    )
    return field, field_bytes + tag_bytes


class Field(_Serializable):
    __slots__ = ('id', 'value', 'excess_tag_bytes',)

    def __init__(self, field_id, value, excess_tag_bytes=0):
        self.id = field_id
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

    def _iter_pretty(self, indent, depth):
        yield f'{type(self).__name__}({repr(self.id)}, '
        yield from self.value._iter_pretty(indent, depth)
        if self.excess_tag_bytes:
            yield f', excess_tag_bytes={repr(self.excess_tag_bytes)}'
        yield ')'

    @classmethod
    def parse(cls, field_id, wire_type, excess_tag_bytes, data, offset):
        value_klass = VALUE_TYPES.get(wire_type)
        if not value_klass:
            raise ValueError(f'Invalid or unsupported field wire type '
                             f'{wire_type} in tag at position {offset}')
        value, value_bytes = value_klass.parse(data, offset)
        return cls(field_id, value, excess_tag_bytes), value_bytes

    def parse_submessage(self, parse_empty=False):
        """
        Parse the value of this field as a submessage, change its value from a
        Blob to a SubMessage type. Does nothing if the field is already a
        parsed submessage. Returns True if the value parsed successfully.

        Raises an error if the field is of the wrong type or does not parse
        cleanly.
        """
        if isinstance(self.value, Blob):
            if len(self.value.value) > 0 or parse_empty:
                self.value = SubMessage(
                    self.value.message.fields,
                    self.value.excess_bytes
                )
                return True
            else:
                return False  # not parsing empty value
        elif isinstance(self.value, SubMessage):
            return True  # already parsed
        else:
            raise ValueError('Cannot parse non-Blob field value')

    def autoparse_recursive(self, parse_empty=False):
        """
        Recursively parse submessages whenever possible, returning the total
        number of submessages parsed thusly.
        """
        return _recursive_autoparse((self,), parse_empty)

    def unparse_submessage(self):
        """
        Convert this field from a parsed SubMessage to an opaque Blob.

        Noop if this field is already a Blob type.
        """
        if isinstance(self.value, SubMessage):
            self.value = Blob(self.value.serialize(), self.value.excess_bytes)

    def is_default(self):
        return self.value.value == self.value.default_value

    def total_excess_bytes(self):
        return self.excess_tag_bytes + self.value.total_excess_bytes()

    def strip_excess_bytes(self):
        self.excess_tag_bytes = 0
        self.value.strip_excess_bytes()

    def byte_size(self):
        return (
            bytes_to_encode_tag(self.id) +
            self.excess_tag_bytes +
            self.value.byte_size()
        )

    def iter_serialize(self):
        yield write_varint(
            (self.id << 3) | self.value.wire_type,
            self.excess_tag_bytes
        )
        yield from self.value.iter_serialize()


class Group(_FieldSet):
    __slots__ = ('id', 'excess_tag_bytes', 'excess_end_tag_bytes')

    def __init__(
        self, group_id, fields=(),
        excess_tag_bytes=0, excess_end_tag_bytes=0
    ):
        super().__init__(fields)
        self.id = group_id
        self.excess_tag_bytes = excess_tag_bytes
        self.excess_end_tag_bytes = excess_end_tag_bytes

    def __repr__(self):
        if self.excess_tag_bytes + self.excess_end_tag_bytes:
            return (
                f'{type(self).__name__}('
                f'{repr(self.id)}, {repr(self.fields)}, '
                f'excess_tag_bytes={repr(self.excess_tag_bytes)}, '
                f'excess_end_tag_bytes={repr(self.excess_end_tag_bytes)}'
                f')'
            )
        else:
            return (
                f'{type(self).__name__}('
                f'{repr(self.id)}, {repr(self.fields)}'
                f')'
            )

    def _pretty_extra_pre(self):
        yield f'{repr(self.id)}, '

    def _pretty_extra_post(self):
        if self.excess_tag_bytes:
            yield f', excess_tag_bytes={repr(self.excess_tag_bytes)}'
        if self.excess_end_tag_bytes:
            yield f', excess_end_tag_bytes={repr(self.excess_end_tag_bytes)}'

    @classmethod
    def parse(cls, _wire_type, field_id, excess_tag_bytes, data, offset):
        excess_end_tag_bytes = 0
        total_bytes_read = 0

        def get_fields(offset_):
            nonlocal excess_end_tag_bytes, total_bytes_read
            while offset_ < len(data):
                field, bytes_read = parse_field(data, offset_)
                offset_ += bytes_read
                total_bytes_read += bytes_read
                if isinstance(field.value, GroupEnd):
                    if field.id != field_id:
                        raise ValueError(f'Non-matching group end tag with id '
                                         f'{field.id} at position {offset}')
                    excess_end_tag_bytes = field.excess_tag_bytes
                    break
                else:
                    yield field
            else:
                # Reached the end of the data without closing the group
                raise ValueError('Message truncated')

        try:
            fields = list(get_fields(offset))
        except ValueError as ex:
            # Append info about this group context to parsing errors
            raise ValueError(
                ex.args[0] + f' in group with id {field_id}'
                             f' which began at position {offset}'
            )
        return cls(
            field_id,
            fields,
            excess_tag_bytes,
            excess_end_tag_bytes
        ), total_bytes_read

    def parse_submessage(self):
        raise ValueError('Groups cannot be parsed')

    def unparse_submessage(self):
        raise ValueError('Groups cannot be unparsed')

    @property
    def value(self):
        """
        This property is used when fields are gotten by id with indexing.
        It makes the most sense to work with an entire group, since it
        manages its own 'value' in the fields attribute.
        """
        return self

    def is_default(self):
        return len(self.fields) == 0

    def byte_size(self):
        return (
            bytes_to_encode_tag(self.id) * 2 +
            self.excess_tag_bytes + self.excess_end_tag_bytes +
            super().byte_size()
        )

    def total_excess_bytes(self):
        return (
            super().total_excess_bytes() +
            self.excess_tag_bytes +
            self.excess_end_tag_bytes
        )

    def strip_excess_bytes(self):
        super().strip_excess_bytes()
        self.excess_tag_bytes = 0
        self.excess_end_tag_bytes = 0

    def iter_serialize(self):
        yield write_varint(
            (self.id << 3) | GroupStart.wire_type,
            self.excess_tag_bytes
        )
        yield from super().iter_serialize()
        yield write_varint(
            (self.id << 3) | GroupEnd.wire_type,
            self.excess_end_tag_bytes
        )


class ProtoValue(_Serializable):
    __slots__ = ('value',)

    def __init__(self, value=None):
        if value is None:
            self.value = self.default_value()
        else:
            self.value = value

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.value == self.value

    def __hash__(self):
        return hash((type(self), self.value))

    def __repr__(self):
        excess_bytes = getattr(self, 'excess_bytes', None)
        if excess_bytes:
            return (
                f'{type(self).__name__}({repr(self.value)}, '
                f'excess_bytes={excess_bytes})'
            )
        else:
            return f'{type(self).__name__}({repr(self.value)})'

    def _iter_pretty(self, indent, depth):
        yield repr(self)

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
            raise ValueError(f'Data truncated in length-delimited data '
                             f'beginning at position {start} '
                             f'(was {length} long)')
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
    def bytes(self):
        return self.value

    @bytes.setter
    def bytes(self, value):
        self.value = value

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
            raise TypeError(f'Invalid interpretation {repr(interpretation)} '
                            f'for value klass {value_klass.__name__}')

    def set_as_repeated(self, values, value_klass=None, interpretation='value'):
        def emitter():
            if value_klass is None:
                for value in values:
                    yield from value.iter_serialize()
            else:
                value_writer = value_klass()
                if not hasattr(value_writer, interpretation):
                    raise TypeError(
                        f'Invalid interpretation {repr(interpretation)} for '
                        f'value klass {value_klass.__name__}'
                    )
                for value in values:
                    setattr(value_writer, interpretation, value)
                    yield from value_writer.iter_serialize()

        self.value = b''.join(emitter())

    def get_as_repeated_with_excess_bytes(
            self,
            value_klass,
            interpretation='value'
    ):
        try:
            return [
                (getattr(value, interpretation), value.total_excess_bytes())
                for value in value_klass.parse_repeated(self.value)
            ]
        except AttributeError:
            raise TypeError(f'Invalid interpretation {repr(interpretation)} '
                            f'for value klass {value_klass.__name__}')

    def set_as_repeated_with_excess_bytes(
            self,
            values_with_excess_bytes,
            value_klass,
            interpretation
    ):
        def emitter():
            value_writer = value_klass()
            if not hasattr(value_writer, interpretation):
                raise TypeError(
                    f'Invalid interpretation {repr(interpretation)} for value '
                    f'klass {value_klass.__name__}'
                )
            if not hasattr(value_writer, 'excess_bytes'):
                raise TypeError(f'Value klass {value_klass.__name__} cannot '
                                f'have excess bytes')
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
                            f'Invalid interpretation '
                            f'{repr(key_interpretation)} '
                            f'for key klass {key_klass.__name__}'
                        )
                if value_klass is None:
                    value_field.value = value
                else:
                    try:
                        setattr(value_writer, value_interpretation, value)
                    except AttributeError:
                        raise TypeError(
                            f'Invalid interpretation '
                            f'{repr(value_interpretation)} '
                            f'for value klass {value_klass.__name__}'
                        )
                yield item_msg

        self.set_as_repeated(build_result(), Blob, 'message')


class SubMessage(ProtoMessage):
    """Represents a Blob field interpreted as a valid sub-message."""
    __slots__ = ('excess_bytes',)
    wire_type = 2

    def __init__(self, fields=(), excess_bytes=0):
        super().__init__(fields)
        self.excess_bytes = excess_bytes

    def _pretty_extra_post(self):
        if self.excess_bytes:
            yield f', excess_bytes={repr(self.excess_bytes)}',

    @property
    def default_value(self):
        return ProtoMessage()

    @classmethod
    def parse(cls, data, offset=0):
        length, length_bytes = read_varint(data, offset)
        excess_bytes = length_bytes - bytes_to_encode_varint(length)
        start = offset + length_bytes
        value = ProtoMessage.parse(data[start:start + length])
        return cls(value.fields, excess_bytes), length_bytes + length

    def byte_size(self):
        length = super().byte_size()
        return bytes_to_encode_varint(length) + self.excess_bytes + length

    def total_excess_bytes(self):
        return self.excess_bytes + super().total_excess_bytes()

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(super().byte_size(), self.excess_bytes)
        yield from super().iter_serialize()

    @property
    def bytes(self):
        return b''.join(super().iter_serialize())

    @bytes.setter
    def bytes(self, value):
        self.fields = ProtoMessage.parse(value).fields

    @property
    def message(self):
        return self

    @message.setter
    def message(self, value):
        self.fields = list(value)

    @property
    def text(self):
        return self.bytes.decode('utf-8')


class Fixed32(ProtoValue):
    __slots__ = ()
    wire_type = 5
    default_value = b'\0' * 4

    @classmethod
    def parse(cls, data, offset=0):
        value = data[offset:offset + 4]
        if len(value) < 4:
            raise ValueError(f'Data truncated in fixed32 value beginning at '
                             f'position {offset}')
        return cls(value), 4

    def byte_size(self):
        return 4

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
            raise ValueError(f'Data truncated in fixed64 value beginning at '
                             f'position {offset}')
        return cls(value), 8

    def byte_size(self):
        return 8

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


# noinspection PyMethodMayBeStatic
class _TagOnlyValue(_Serializable):
    __slots__ = ()
    value = None
    default_value = NotImplemented

    def __repr__(self):
        return f'{type(self).__name__}()'

    def _iter_pretty(self, indent, depth):
        yield repr(self)

    @classmethod
    def parse(cls, _data, _offset=0):
        return cls(), 0

    def byte_size(self):
        return 0

    def iter_serialize(self):
        return ()  # nothing


class GroupStart(_TagOnlyValue):
    __slots__ = ()
    wire_type = 3


class GroupEnd(_TagOnlyValue):
    __slots__ = ()
    wire_type = 4


# Mapping from wire type to value klass.
VALUE_TYPES = {
    klass.wire_type: klass
    for klass in [
        Varint,
        Fixed64,
        Blob,
        GroupStart,
        GroupEnd,
        Fixed32,
    ]
}

# These are overrides for the klass of field that parses a given wiretype.
# If a wiretype is not present, defaults to Field.
# Currently only applies to groups. Setting this to an empty dict and passing
# allow_orphan_group_ends=True to ProtoMessage.parse() will return messages
# parsed with explicit GroupStart/GroupEnd fields instead of actual groups.
FIELD_TYPES = {
    GroupStart.wire_type: Group
}
