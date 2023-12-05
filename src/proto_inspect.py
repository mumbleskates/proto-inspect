# coding=utf-8
from collections.abc import Iterable
from operator import attrgetter
from struct import pack, unpack
from typing import Union

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

    * repr_pretty(), pretty_print()
        Outputs the same valid code that reproduces the object like repr does,
        but broken into multiple lines with hierarchical indents. The number of
        spaces for the indentation is customizable with the indent argument.
        repr_pretty() returns the pretty as a string, and pretty_print sends it
        to print() for convenience.

    * operators ==, hash()
        Note: These objects are mutable, and hash() is not safe if you plan to
        change their values.

    * byte_size()
        Returns the exact number of bytes when serialized.

    * total_excess_bytes()
        Returns the number of bytes the message would be shortened by if all
        extraneous varint bytes are removed.

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


APIs unique to values (Varint, Blob, Fixed4Bytes, Fixed8Bytes, PackedRepeated,
SubMessage, Group):

    * is_default()
        Returns a boolean value, true if this value is its proto3 default.

    * excess_bytes
        If a value contains a varint, it will have this attribute. It can be set
        to arbitrary non-negative integers; however, values that result in a
        serialized varint length of over 10 bytes may not be valid or readable
        at all by other proto parsing libraries.

    * parse(data, offset=0)
        Returns an instance of the value read from the given data and offset,
        and the number of bytes consumed (as a 2-tuple).

    * parse_repeated(data, offset=0, limit=inf)
        Returns a generator that repeatedly consumes from the given data and
        offset, returning only the data each time. Terminates when it reads to
        the end of the data or the offset described by limit cleanly, whichever
        comes first. Used for reading the values from e.g. packed repeated
        fields, which are stored with variable-length (Blob) wire type and
        contain only the values concatenated together, omitting the tags.

    * parse_submessage():
        Returns the value in submessage form, or raises an error if the value
        cannot be a submessage.

    Typed access properties:
        Provides get/set views of the values translated for the given
        representation:

        Varint:
            unsigned, signed, bool,
            uint32, int32, sint32,
            uint64, int64, sint64
            value: un-translated int value

        Fixed4Bytes:
            float4 (alias single), fixed32, sfixed32
            value: 4-character bytes object

        Fixed8Bytes:
            float8 (alias double), fixed64, sfixed64
            value: 8-character bytes object

        Blob:
            bytes (plain bytes object), string (utf-8),
            message (nested protobuf message)
            value: plain bytes object


APIs unique to fields:
    * parse_submessage()
        TODO: document

    * unparsed()
        TODO: document


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

    * paths_and_values()
        Recursively yields all the values in the proto with the paths of field
        ids traversed to reach them.
"""

UNSIGNED_64_BIT_RANGE = range(0x1_0000_0000_0000_0000)
SIGNED_64_BIT_RANGE = range(-0x8000_0000_0000_0000, 0x8000_0000_0000_0000)
UNSIGNED_32_BIT_RANGE = range(0x1_0000_0000)
SIGNED_32_BIT_RANGE = range(-0x8000_0000, 0x8000_0000)

# ProtoValue klasses by name of proto type (e.g., int64, string, double etc.)
VALUE_TYPE_KLASSES = {}


def _register_value_types(*types):
    global VALUE_TYPE_KLASSES

    def dec(klass):
        for type_name in types:
            # ensure the klass has an accessor for that name
            assert hasattr(klass, type_name), f'{klass} missing {type_name}'
            VALUE_TYPE_KLASSES[type_name] = klass
        return klass

    return dec


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


def write_varint(value, *, excess_bytes=0):
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
        raise ValueError('Encoded varint must be non-negative')
    elif value == 0:
        return b'\0'
    else:
        return bytes(varint_bytes(value))


def read_varint(data, *, offset=0):
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
        raise ValueError('Encoded varint must be non-negative')
    return max(1, (n.bit_length() + 6) // 7)


def bytes_to_encode_tag(tag_id):
    """
    Return the minimum number of bytes needed to represent a tag with a given
    id.
    """
    return (tag_id.bit_length() + 9) // 7


def _recursive_autoparse(fields, parse_empty):
    """
    Auto-parses fields into submessages recursively, returning the number
    of submessages successfully parsed.
    """
    num_parsed = 0
    for field in fields:
        try:
            if not isinstance(field.value, _FieldSet):
                field.parse_submessage(parse_empty=parse_empty)
                num_parsed += 1
            num_parsed += _recursive_autoparse(
                field.value.fields,
                parse_empty
            )
        except (TypeError, ValueError):
            pass
    return num_parsed


class _Serializable:
    __slots__ = ()

    def iter_pretty(self, indent, depth):
        raise NotImplementedError

    def repr_pretty(self, indent=4):
        return ''.join(self.iter_pretty(' ' * indent, 0))

    def pretty_print(self, *args, **kwargs):
        print(self.repr_pretty(*args, **kwargs))

    def byte_size(self):
        raise NotImplementedError

    def total_excess_bytes(self):
        return 0

    def strip_excess_bytes(self):
        pass

    def iter_serialize(self):
        raise NotImplementedError

    def serialize(self, **kwargs):
        # noinspection PyArgumentList
        return b''.join(self.iter_serialize(**kwargs))


class _FieldSet(_Serializable):
    __slots__ = ('fields',)
    fields: Union[list, dict]
    delineator_type = ()  # no delineator

    def __init__(self, fields, *, indexed):
        if not isinstance(fields, Iterable):
            raise TypeError(f'Cannot create fieldset with non-iterable type '
                            f'{repr(type(fields).__name__)}')
        if indexed:
            self.fields = {}
            for field in fields:
                self.fields.setdefault(field.id, []).append(field)
        else:
            self.fields = list(fields)

    def __eq__(self, other):
        """
        Calculate equality, ignoring excess varint bytes and un-sorted
        fields.
        """
        if type(other) is not type(self):
            return NotImplemented
        return (
                sorted(other, key=attrgetter('id')) ==
                sorted(self, key=attrgetter('id'))
        )

    def __iter__(self):
        if self.is_indexed():
            for group in self.fields.values():
                yield from group
        else:
            yield from self.fields

    def __repr__(self):
        return f'{type(self).__name__}({repr(self.fields)})'

    def iter_pretty(self, indent, depth):
        if self.fields:
            yield f'{type(self).__name__}('
            if self.is_indexed():
                yield '{\n'
                for index, group in self.fields.items():
                    if group:
                        yield indent * (depth + 1)
                        yield f'{index}: [\n'
                        for field in group:
                            yield indent * (depth + 2)
                            yield from field.iter_pretty(indent, depth + 2)
                            yield ',\n'
                        yield indent * (depth + 1)
                        yield '],\n'
                yield f'{indent * depth}}}'
            else:
                yield '[\n'
                for field in self:
                    yield indent * (depth + 1)
                    yield from field.iter_pretty(indent, depth + 1)
                    yield ',\n'
                yield f'{indent * depth}]'
            yield from self._pretty_extra_post()
            yield ')'
        else:
            yield repr(self)

    def _pretty_extra_post(self):
        return ()

    def copy(self):
        return type(self)(
            (field.copy() for field in self),
            indexed=self.is_indexed()
        )
    __deepcopy__ = copy

    def is_indexed(self):
        return isinstance(self.fields, dict)

    def make_indexed(self):
        """
        Makes this message or group indexed. If it is already indexed but some
        of the fields in the message have had their id changed, this reindexes
        the fields so they are all accessible by their id.
        """
        new_fields = {}
        for field in self:
            new_fields.setdefault(field.id, []).append(field)
        self.fields = new_fields

    def make_flat(self):
        """Flattens the representation of the fields to a fully ordered list."""
        self.fields = list(self)

    def _map_fields(self, transform_fn, field_ids=None):
        """
        Returns a copy of fields with the given transformation.

        If field_ids is None, passes all fields to the transform fn. If it is a
        container of field ids, only fields with a contained id will be mapped.

        If the transform fn returns None, the field will be removed.
        """
        if field_ids is None:
            field_ids = UNSIGNED_64_BIT_RANGE
        elif not isinstance(field_ids, Iterable):
            field_ids = (field_ids,)

        if self.is_indexed():
            new_fields = {}
            for index, group in self.fields.items():
                if index in field_ids:
                    transformed = [
                        item for item in map(transform_fn, group)
                        if item is not None
                    ]
                    if transformed:  # Only carry over non-empty groups
                        new_fields[index] = transformed
                else:
                    new_fields[index] = group
        else:
            new_fields = []
            for field in self.fields:
                if field.id in field_ids:
                    transformed = transform_fn(field)
                    if transformed is not None:
                        new_fields.append(transformed)
                else:
                    new_fields.append(field)

        return new_fields

    @classmethod
    def parse(
            cls,
            data,
            *,
            offset=0,
            limit=float('inf'),
            indexed=False,
            explicit_group_markers=False,
            field_id=None,
    ):
        """
        Parse a complete field set from a bytes-like object.

        Starts parsing from the given offset and consumes until the end of the
        data or the given limit (another greater or equal offset) is reached,
        whichever comes first. Fails if the end of the fields does not fit
        exactly to the end of the data (or the limit).

        If indexed is set to True, the message's fields will be stored indexed
        by field id. This loses information about the exact ordering of fields
        (for example, if field 1 is repeated but has other fields interspersed
        in between).

        If explicit_group_markers is set to True, rather than parsing groups as
        nested structures (and validating that group end tags correctly match),
        GroupStart and GroupEnd field tags will be listed explicitly in the
        parsed fields, with any nesting of fields and other groups inside groups
        flattened to the top level. (This is for debugging. Note that this makes
        no sense in combination with indexed mode.)
        """
        extra_args = {}
        total_bytes_read = 0

        def get_fields():
            nonlocal total_bytes_read
            current_offset = offset
            found_delineator = False if cls.delineator_type else True
            while current_offset < len(data) and current_offset < limit:
                field, bytes_read = Field.parse(
                    data, offset=current_offset,
                    explicit_group_markers=explicit_group_markers
                )
                current_offset += bytes_read
                if (
                        isinstance(field.value, cls.delineator_type)
                        and not explicit_group_markers
                ):
                    if field.id != field_id:
                        raise ValueError(
                            f'Non-matching delineator for {cls.__name__} '
                            f'with id {field.id} at position '
                            f'{current_offset - bytes_read}'
                        )
                    extra_args['excess_end_tag_bytes'] = field.excess_tag_bytes
                    found_delineator = True
                    break
                if (
                        isinstance(field.value, GroupEnd) and
                        not explicit_group_markers
                ):
                    raise ValueError(f'Orphaned group end with id {field.id} '
                                     f'at position {current_offset}')
                yield field
            if current_offset > limit:
                raise ValueError(
                    f'{cls.__name__} truncated (overran limit at position '
                    f'{limit}) in fieldset starting at position {offset}'
                )
            if not found_delineator:
                raise ValueError(
                    f'{cls.__name__} truncated (reached limit at position '
                    f'{limit} without finding delineator) '
                    f'in fieldset starting at position {offset}'
                )
            total_bytes_read = current_offset - offset

        try:
            # Extra args are intentional.
            # noinspection PyArgumentList
            return (
                cls(get_fields(), indexed=indexed, **extra_args),
                total_bytes_read
            )
        except ValueError as ex:
            if field_id:
                raise ValueError(
                    f'{ex.args[0]} in group with id {field_id} '
                    f'which began at position {offset}'
                )
            raise

    def field_list(self, field_id):
        """
        Returns a list of fields with the given id.

        If this field set is indexed and some fields have had their field ids
        changed, this method may return incorrect results until it is reindexed
        (by calling make_indexed() again).
        """
        if self.is_indexed():
            return list(self.fields.get(field_id, ()))
        else:
            return [field for field in self if field.id == field_id]

    def value_list(self, field_id):
        """
        Returns a list of values from fields with the given id.

        If this field set is indexed and some fields have had their field ids
        changed, this method may return incorrect results until it is reindexed
        (by calling make_indexed() again).
        """
        return [field.value for field in self.field_list(field_id)]

    def __getitem__(self, field_id):
        """
        Like value_list, but single results are unwrapped from the list for
        convenience, and lack of results raises a KeyError instead of returning
        an empty list.
        """
        result = self.value_list(field_id)
        if not result:
            raise KeyError(f'Field not found: {repr(field_id)}')
        if len(result) == 1:
            single = result[0]
            if isinstance(single, PackedRepeated):
                return list(single.values)
            else:
                return single
        else:
            return result

    def __setitem__(self, field_id, value):
        """
        Replaces the existing fields with the given id with the single value
        (or iterable of values) provided.

        If a field or fields of this id already existed, the new fields will be
        inserted consecutively at the position of the first occurrence of that
        field id. If no fields with this id previously existed, the new fields
        will be appended at the end.
        """
        if isinstance(value, _FieldSet):
            # If it's a plain message, make a SubMessage
            fields_to_add = [
                Field(field_id, SubMessage(value, indexed=value.is_indexed()))
            ]
        elif (  # value is iterable, but not one of the iterable value types
                isinstance(value, Iterable) and
                not isinstance(value, (ProtoMessage, PackedRepeated))
        ):
            fields_to_add = [Field(field_id, val) for val in value]
        else:
            fields_to_add = [Field(field_id, value)]

        if not fields_to_add:
            del self[field_id]
            return

        if self.is_indexed():
            self.fields[field_id] = fields_to_add
        else:
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
        """Removes all fields with the given id."""
        if self.is_indexed():
            self.fields.pop(field_id, None)
        else:
            self.fields = [field for field in self if field.id != field_id]

    def sort(self):
        """Order the fields in this message by id."""
        if self.is_indexed():
            self.fields = dict(sorted(self.fields.items()))
        else:
            self.fields.sort(key=attrgetter('id'))

    # TODO: parse_multi_packed_repeated

    def parse_multi_submessages(
            self,
            field_ids=None,
            *,
            auto=False,
            auto_parse_empty=False,
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
        num_parsed = 0

        def parse_submessage_transform(field):
            nonlocal num_parsed
            if not isinstance(field.value, (Blob, SubMessage)):
                raise ValueError(
                    f'Encountered field at specified id {field.id} with '
                    f'non-Blob type {type(field.value).__name__}'
                )
            if (
                    isinstance(field.value, Blob) and
                    (len(field.value.value) > 0 or auto_parse_empty)
            ):
                try:
                    parsed = Field(
                        field.id,
                        SubMessage(
                            field.value.message,
                            excess_bytes=field.value.excess_bytes
                        ),
                        excess_tag_bytes=field.excess_tag_bytes
                    )
                    num_parsed += 1
                    return parsed
                except ValueError:
                    if auto:
                        return field
                    else:
                        raise
            else:
                return field

        self.fields = self._map_fields(parse_submessage_transform, field_ids)
        return num_parsed

    def autoparse_recursive(self, *, parse_empty=False):
        # TODO: wrap functionality into parse_multi_submessages
        """
        Recursively parse submessages whenever possible, returning the total
        number of submessages parsed thusly.
        """
        # These calls mutate as they go rather than building a speculative list
        # of altered fields (like unparse_fields does) because if we are only
        # trying to parse anything that *can* be parsed and there is no failure
        # mode.
        return _recursive_autoparse(self, parse_empty)

    def unparse_fields(self, field_ids=None):
        """
        Replace SubMessage and PackedRepeated fields at the specified ids with
        their serialized Blob values.

        If field_ids is None, performs this action on all fields.
        """
        num_unparsed = 0

        def unparse_transform(field):
            nonlocal num_unparsed
            unparsed = field.unparsed()
            if unparsed is not field:
                num_unparsed += 1
            return unparsed

        self.fields = self._map_fields(unparse_transform, field_ids)
        return num_unparsed

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
        fields_stripped = 0

        def strip_default_transform(field):
            nonlocal fields_stripped
            if field.is_default():
                fields_stripped += 1
                return None
            else:
                return field

        self.fields = self._map_fields(strip_default_transform, self.fields)
        return fields_stripped

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

    def paths_and_fields(self, *, path_prefix=()):
        """
        Yields (path, field) tuples for each field and sub-field in the proto,
        recursively. The path will be a tuple of field number ints; for
        example, the path (1,) represents that the field has id 1 at the top
        level; (2, 3, 2, 1) means that it is at field 1, inside field 2, inside
        field 3, inside field 2 at the top level. The given path does not
        include any information about where in repeated fields the value exists,
        and so is not sufficient to completely locate that exact field.

        This can be used to build a complete accounting of which fields and
        subfields of a proto are consuming the most space, for example:

        account = collections.Counter()
        for path, field in msg.paths_and_fields():
            account[path] += field.byte_size()

        ...or perhaps to programmatically find at which path in the proto a
        certain value occurs with a full search. See also: paths_and_values()
        """
        for field in self.fields:
            this_path = (*path_prefix, field.id)
            yield this_path, field
            if isinstance(field.value, _FieldSet):
                yield from field.value.paths_and_fields(path_prefix=this_path)

    def paths_and_values(self, *, path_prefix=()):
        """
        Yields the same results as paths_and_fields, but unwraps the field
        values first.
        """
        for path, field in self.paths_and_fields(path_prefix=path_prefix):
            yield path, field.value

    def iter_serialize(self):
        for field in self:
            yield from field.iter_serialize()

    # TODO: implement and document map accessors (maybe as a view?); delegate to
    #  PackedRepeated if that's what's found


class ProtoMessage(_FieldSet):
    __slots__ = ()

    def __init__(self, fields=(), *, indexed=False):
        """
        Create a new ProtoMessage with the given iterable of protobuf Fields.
        """
        super().__init__(fields, indexed=indexed)

    # This method intentionally has a different signature than super's.
    # noinspection PyMethodOverriding
    @classmethod
    def parse(
            cls,
            data,
            *,
            offset=0,
            limit=float('inf'),
            indexed=False,
            explicit_group_markers=False,
    ):
        result, bytes_read = super().parse(
            data,
            offset=offset,
            limit=limit,
            indexed=indexed,
            explicit_group_markers=explicit_group_markers
        )
        return result

    @property
    def message(self):
        return self


class Field(_Serializable):
    __slots__ = ('id', 'value', 'excess_tag_bytes',)

    def __init__(self, field_id, value, *, excess_tag_bytes=0):
        self.id = field_id
        self.value = value
        self.excess_tag_bytes = excess_tag_bytes

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.id == self.id and other.value == self.value

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

    def iter_pretty(self, indent, depth):
        yield f'{type(self).__name__}({repr(self.id)}, '
        yield from self.value.iter_pretty(indent, depth)
        if self.excess_tag_bytes:
            yield f', excess_tag_bytes={repr(self.excess_tag_bytes)}'
        yield ')'

    @classmethod
    def parse(cls, data, *, offset=0, explicit_group_markers=False):
        try:
            tag, tag_bytes = read_varint(data, offset=offset)
        except ValueError as ex:
            raise ValueError(f'{ex.args[0]} while parsing field tag')
        field_id = tag >> 3
        wire_type = tag & 0b111
        excess_tag_bytes = tag_bytes - bytes_to_encode_tag(field_id)
        try:
            if explicit_group_markers:
                value_klass = WIRE_TYPE_KLASSES_EXPLICIT_GROUP[wire_type]
            else:
                value_klass = WIRE_TYPE_KLASSES[wire_type]
        except KeyError:
            raise ValueError(f'Invalid or unsupported field wire type '
                             f'{wire_type} in tag at position {offset}')
        value, value_bytes = value_klass.parse(
            data, offset=offset + tag_bytes, field_id=field_id
        )
        return (
            cls(field_id, value, excess_tag_bytes=excess_tag_bytes),
            tag_bytes + value_bytes
        )

    def copy(self):
        return type(self)(
            self.id,
            self.value.copy(),
            excess_tag_bytes=self.excess_tag_bytes
        )
    __deepcopy__ = copy

    def parse_packed_repeated(self, repeated_value_type):
        """
        Parse the value of this field as a packed repeated field, changing its
        value from a Blob to a PackedRepeated type.

        This method changes the representation of the field, but not its
        serialized value -- only the form of its interpretation.

        Raises a TypeError if the value is not a Blob, or a ValueError if it
        does not parse cleanly.
        """
        # TODO: rejigger this to be on values probably, and non-mutating
        if not isinstance(self.value, Blob):
            raise TypeError(
                'Cannot parse non-Blob field value as a packed repeated value.'
            )

        self.value = PackedRepeated(
            repeated_value_type.parse_repeated(self.value.value),
            excess_bytes=self.value.excess_bytes
        )

    def parse_submessage(self, *, parse_empty=False):
        """
        Parse the value of this field as a submessage, changeing its value from
        a Blob to a SubMessage type. Does nothing if the field is already a
        parsed submessage. Returns True if the value is now parsed as a
        submessage, or False if the value was empty.

        This method changes the representation of the field, but not its
        serialized value -- only the form of its interpretation.

        Raises a TypeError if the field is of the wrong type (not a Blob), or a
        ValueError if it does not parse cleanly.
        """
        self.value = self.value.parse_submessage(parse_empty=parse_empty)

    def autoparse_recursive(self, *, parse_empty=False):
        """
        Recursively parse submessages whenever possible, returning the total
        number of submessages parsed thusly.
        """
        return _recursive_autoparse((self,), parse_empty)

    def unparsed(self):
        """
        Return a new field with the same value as this field, converted from a
        parsed SubMessage or PackedRepeated to an opaque Blob.

        Returns this object if this field already has a Blob type.
        """
        # TODO: document up top
        if type(self.value) is Blob:
            return self
        elif self.value.wire_type == Blob.wire_type:
            return Field(
                self.id,
                Blob(self.value.bytes, excess_bytes=self.value.excess_bytes),
                excess_tag_bytes=self.excess_tag_bytes
            )
        else:
            raise TypeError(
                f'Cannot unparse a value of type {type(self.value).__name__}'
            )

    def is_default(self):
        return self.value.is_default

    def total_excess_bytes(self):
        return self.excess_tag_bytes + self.value.total_excess_bytes()

    def strip_excess_bytes(self):
        self.excess_tag_bytes = 0
        self.value.strip_excess_bytes()

    def byte_size(self):
        return (
                bytes_to_encode_tag(self.id) +
                self.excess_tag_bytes +
                self.value.byte_size() +
                self.value.delineator_size(field_id=self.id)
        )

    def iter_serialize(self):
        yield write_varint(
            (self.id << 3) | self.value.wire_type,
            excess_bytes=self.excess_tag_bytes
        )
        yield from self.value.iter_serialize()
        yield from self.value.delineator_iter_serialize(field_id=self.id)


class _ParseableValue:
    """Mixin for values which can be parsed once or repeatedly."""
    __slots__ = ()

    @classmethod
    def parse(cls, data, *, offset=0, field_id=None):
        raise NotImplementedError

    @classmethod
    def parse_repeated(cls, data, *, offset=0, limit=float('inf')):
        """
        Parses a repeated proto value from a bytes-like object.

        Starts parsing from the given offset and consumes until the end of the
        data or the given limit (another greater or equal offset) is reached,
        whichever comes first. Fails if the end of the message does not fit
        exactly to the end of the data (or the limit).
        """
        current_offset = offset
        while current_offset < len(data) and current_offset < limit:
            value, value_bytes = cls.parse(data, offset=current_offset)
            yield value
            current_offset += value_bytes
        if current_offset > limit:
            raise ValueError(
                f'Data truncated (overran limit at position {limit}) '
                f'in repeated {cls.__name__} '
                f'starting at position {offset}'
            )


# noinspection PyAbstractClass
class _ProtoValue(_Serializable):
    __slots__ = ()

    def is_default(self):
        raise NotImplementedError

    @property
    def wire_type(self):
        raise NotImplementedError

    @classmethod
    def parse_submessage(cls, *, parse_empty=False):
        raise ValueError(
            f'Value of type {cls.__name__} cannot be parsed as a submessage'
        )

    def delineator_size(self, field_id):
        return 0

    def delineator_iter_serialize(self, field_id):
        return ()


# noinspection PyAbstractClass
class _SingleValue(_ProtoValue, _ParseableValue):
    __slots__ = ('value',)

    def __init__(self, value=None):
        if value is None:
            self.value = self.default_value
        else:
            self.value = value

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.value == self.value

    def __repr__(self):
        excess_bytes = getattr(self, 'excess_bytes', None)
        if excess_bytes:
            return (
                f'{type(self).__name__}({repr(self.value)}, '
                f'excess_bytes={excess_bytes})'
            )
        else:
            return f'{type(self).__name__}({repr(self.value)})'

    @property
    def default_value(self):
        raise NotImplementedError

    def is_default(self):
        return self.value == self.default_value

    def iter_pretty(self, indent, depth):
        yield repr(self)

    def copy(self):
        return type(self)(self.value)
    __deepcopy__ = copy


@_register_value_types(
    'varint',
    'unsigned',
    'signed',
    'bool',
    'int32',
    'int64',
    'uint32',
    'uint64',
    'sint32',
    'sint64',
)
class Varint(_SingleValue):
    __slots__ = ('excess_bytes',)
    wire_type = 0
    default_value = 0

    def __init__(self, value=None, *, excess_bytes=0):
        super().__init__(value)
        self.excess_bytes = excess_bytes

    @classmethod
    def parse(cls, data, *, offset=0, field_id=None):
        value, value_bytes = read_varint(data, offset=offset)
        excess_bytes = value_bytes - bytes_to_encode_varint(value)
        return cls(value, excess_bytes=excess_bytes), value_bytes

    def byte_size(self):
        return bytes_to_encode_varint(self.value) + self.excess_bytes

    def total_excess_bytes(self):
        return self.excess_bytes

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(self.value, excess_bytes=self.excess_bytes)

    @property
    def varint(self):
        return self.value

    @varint.setter
    def varint(self, value):
        if value < 0:
            raise ValueError('Varint value must be non-negative')
        self.value = value

    unsigned = varint

    @property
    def signed(self):
        return uint_to_signed(self.value)

    @signed.setter
    def signed(self, value):
        self.value = signed_to_uint(value)

    @property
    def bool(self):
        return bool(self.value)

    @bool.setter
    def bool(self, value):
        self.value = int(bool(value))

    @property
    def uint32(self):
        if self.value not in UNSIGNED_32_BIT_RANGE:
            raise ValueError('Varint out of range for uint32')
        return self.value

    @uint32.setter
    def uint32(self, value):
        if value not in UNSIGNED_32_BIT_RANGE:
            raise ValueError('Value out of range for uint32')
        self.value = value

    @property
    def int32(self):
        if self.value not in UNSIGNED_64_BIT_RANGE:
            raise ValueError('Varint out of range for int32')
        n = self.value
        if n & 0x8000_0000_0000_0000:
            n = n - 0x1_0000_0000_0000_0000
        if n not in SIGNED_32_BIT_RANGE:
            raise ValueError('Varint out of range for int32')
        return n

    @int32.setter
    def int32(self, value):
        if value not in SIGNED_32_BIT_RANGE:
            raise ValueError('Value out of range for int32')
        self.value = value & 0xffff_ffff_ffff_ffff

    @property
    def sint32(self):
        if self.value not in UNSIGNED_32_BIT_RANGE:
            raise ValueError('Varint out of range for sint32')
        return uint_to_signed(self.value)

    @sint32.setter
    def sint32(self, value):
        if value not in SIGNED_32_BIT_RANGE:
            raise ValueError('Value out of range for sint32')
        self.value = signed_to_uint(value)

    @property
    def uint64(self):
        if self.value not in UNSIGNED_64_BIT_RANGE:
            raise ValueError('Varint out of range for uint64')
        return self.value

    @uint64.setter
    def uint64(self, value):
        if value not in UNSIGNED_64_BIT_RANGE:
            raise ValueError('Value out of range for uint64')
        self.value = value

    @property
    def int64(self):
        if self.value not in UNSIGNED_64_BIT_RANGE:
            raise ValueError('Varint out of range for int64')
        if self.value & 0x8000_0000_0000_0000:
            return self.value - 0x1_0000_0000_0000_0000
        else:
            return self.value

    @int64.setter
    def int64(self, value):
        if value not in SIGNED_64_BIT_RANGE:
            raise ValueError('Value out of range for int64')
        self.value = value & 0xffff_ffff_ffff_ffff

    @property
    def sint64(self):
        if self.value not in UNSIGNED_64_BIT_RANGE:
            raise ValueError('Varint out of range for sint64')
        return uint_to_signed(self.value)

    @sint64.setter
    def sint64(self, value):
        if value not in SIGNED_64_BIT_RANGE:
            raise ValueError('Value out of range for sint64')
        self.value = signed_to_uint(value)


@_register_value_types(
    'fixed4bytes',
    'float4',
    'fixed32',
    'sfixed32',
)
class Fixed4Bytes(_SingleValue):
    __slots__ = ()
    wire_type = 5
    default_value = b'\0' * 4

    @classmethod
    def parse(cls, data, *, offset=0, field_id=None):
        value = data[offset:offset + 4]
        if len(value) < 4:
            raise ValueError(f'Data truncated in Fixed4Bytes value '
                             f'beginning at position {offset}')
        return cls(value), 4

    def byte_size(self):
        return 4

    def iter_serialize(self):
        yield self.value

    @property
    def fixed4bytes(self):
        return self.value

    @fixed4bytes.setter
    def fixed4bytes(self, value):
        if len(value) != 4:
            raise ValueError('Fixed4Bytes value must have length 4')
        self.value = value

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


@_register_value_types(
    'fixed8bytes',
    'float8',
    'double',
    'fixed64',
    'sfixed64',
)
class Fixed8Bytes(_SingleValue):
    __slots__ = ()
    wire_type = 1
    default_value = b'\0' * 8

    @classmethod
    def parse(cls, data, *, offset=0, field_id=None):
        value = data[offset:offset + 8]
        if len(value) < 8:
            raise ValueError(f'Data truncated in Fixed8Bytes value '
                             f'beginning at position {offset}')
        return cls(value), 8

    def byte_size(self):
        return 8

    def iter_serialize(self):
        yield self.value

    @property
    def fixed8bytes(self):
        return self.value

    @fixed8bytes.setter
    def fixed8bytes(self, value):
        if len(value) != 8:
            raise ValueError('Fixed4Bytes value must have length 8')
        self.value = value

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


@_register_value_types(
    'blob',
    'string',
    'bytes',
)
class Blob(_SingleValue):
    __slots__ = ('excess_bytes',)
    wire_type = 2
    default_value = b''

    def __init__(self, value=None, *, excess_bytes=0):
        super().__init__(value)
        self.excess_bytes = excess_bytes

    @classmethod
    def parse(cls, data, *, offset=0, field_id=None):
        try:
            length, length_bytes = read_varint(data, offset=offset)
        except ValueError as ex:
            raise ValueError(
                f'{ex.args[0]} while parsing length of {type(cls).__name__}'
            )
        excess_bytes = length_bytes - bytes_to_encode_varint(length)
        start = offset + length_bytes
        value = data[start:start + length]
        if len(value) < length:
            raise ValueError(f'Data truncated in length-delimited data '
                             f'beginning at position {start} '
                             f'(was {length} long)')
        return cls(value, excess_bytes=excess_bytes), length_bytes + length

    def byte_size(self):
        length = len(self.value)
        return bytes_to_encode_varint(length) + self.excess_bytes + length

    def total_excess_bytes(self):
        return self.excess_bytes

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(len(self.value), excess_bytes=self.excess_bytes)
        yield self.value

    def parse_submessage(self, *, parse_empty=False):
        if self.value or parse_empty:
            return SubMessage(
                self.message,
                excess_bytes=self.excess_bytes
            )
        else:
            raise ValueError('Not parsing empty field as submessage')

    def copy(self):
        clone = super().copy()
        # noinspection PyUnresolvedReferences,PyDunderSlots
        clone.excess_bytes = self.excess_bytes
        return clone
    __deepcopy__ = copy

    @property
    def blob(self):
        return self.value

    @blob.setter
    def blob(self, value):
        self.value = value

    @property
    def bytes(self):
        return self.value

    @bytes.setter
    def bytes(self, value):
        self.value = value

    @property
    def string(self):
        return self.value.decode('utf-8')

    @string.setter
    def string(self, value):
        self.value = value.encode('utf-8')

    @property
    def message(self):
        return ProtoMessage.parse(self.value)

    @message.setter
    def message(self, value):
        self.value = value.serialize()

    # TODO: implement and document map accessors (maybe as a view?)


class PackedRepeated(_ProtoValue):
    """Represents a Blob field interpreted as a valid packed repeated field."""
    __slots__ = ('values', 'excess_bytes',)
    wire_type = Blob.wire_type

    def __init__(self, values=(), *, value_type=None, excess_bytes=0):
        self.values = None  # suppress 'set outside __init__' warning
        self.set_as(values, value_type=value_type)
        self.excess_bytes = excess_bytes

    @property
    def is_default(self):
        return not self.values

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return other.values == self.values

    def __iter__(self):
        yield from self.values

    def __repr__(self):
        if self.excess_bytes:
            return (
                f'{type(self).__name__}('
                f'{repr(self.values)}, '
                f'excess_bytes={self.excess_bytes}'
                f')'
            )
        else:
            return f'{type(self).__name__}({repr(self.values)})'

    def iter_pretty(self, indent, depth):
        if self.values:
            yield f'{type(self).__name__}([\n'
            for value in self.values:
                yield indent * (depth + 1)
                yield from value.iter_pretty(indent, depth + 1)
                yield ',\n'
            yield f'{indent * depth}]'
            if self.excess_bytes:
                yield f', excess_tag_bytes={self.excess_bytes}'
            yield ')'

    def byte_size(self):
        length = sum(value.byte_size() for value in self.values)
        return bytes_to_encode_varint(length) + self.excess_bytes + length

    def total_excess_bytes(self):
        return (
                sum(value.total_excess_bytes() for value in self.values) +
                self.excess_bytes
        )

    def strip_excess_bytes(self):
        self.excess_bytes = 0
        for value in self.values:
            value.strip_excess_bytes()

    def iter_serialize(self):
        # Not exactly efficient, but we're not prescient.
        length = sum(value.byte_size() for value in self.values)
        yield write_varint(length, excess_bytes=self.excess_bytes)
        for value in self.values:
            yield from value.iter_serialize()

    # noinspection PyUnusedLocal
    @classmethod
    def parse(cls, repeated_value_type, data, *, offset=0, field_id=None):
        try:
            length, length_bytes = read_varint(data, offset=offset)
        except ValueError as ex:
            raise ValueError(
                f'{ex.args[0]} while parsing length of {type(cls).__name__}'
            )
        return cls(
            repeated_value_type.parse_repeated(
                data,
                offset=offset + length_bytes,
                limit=offset + length_bytes + length
            ),
            excess_bytes=length_bytes - bytes_to_encode_varint(length)
        )

    def copy(self):
        return type(self)(
            (value.copy() for value in self),
            excess_bytes=self.excess_bytes
        )
    __deepcopy__ = copy

    @property
    def bytes(self):
        return b''.join(
            part
            for value in self.values
            for part in value.iter_serialize()
        )

    @bytes.setter
    def bytes(self, value):
        if self.values:
            repeated_type = type(self.values[0])
            self.values = list(repeated_type.parse_repeated(value))
        elif value == b'':
            self.values = []
        else:
            raise TypeError(
                'The value type of a PackedRepeated cannot be inferred when no '
                'values already exist. Use '
                'set_as(value_type.parse_repeated(value)) with the desired '
                'value type (e.g. Varint, Blob, etc.).'
            )

    def get_as(self, interpretation):
        def emitter():
            for value in self.values:
                try:
                    yield getattr(value, interpretation)
                except AttributeError:
                    raise TypeError(
                        f'Invalid interpretation {repr(interpretation)} '
                        f'for value klass {type(value).__name__}'
                    )

        return list(emitter())

    def set_as(self, values, *, value_type=None):
        """
        Set the repeated values of this field.

        The provided value_type should be the format that the values are in.
        For example, say values is a list of ints: if value_type is "varint" or
        "unsigned" they will be wrapped in Varint as raw values, but if
        value_type is "float4" they will be converted to single-precision
        floating point values and wrapped in Fixed4Bytes values.

        If value_type is not provided, the values will be used as-is.
        """

        def ingester():
            if value_type is None:
                yield from values
            else:
                try:
                    value_klass = VALUE_TYPE_KLASSES[value_type]
                except KeyError:
                    raise ValueError(f'Unknown value type {repr(value_type)}')
                for value in values:
                    proto_value = value_klass()
                    setattr(proto_value, value_type, value)
                    yield proto_value

        self.values = list(ingester())


@_register_value_types(
    'message',
)
class SubMessage(ProtoMessage, _ProtoValue, _ParseableValue):
    """Represents a Blob field interpreted as a valid sub-message."""
    __slots__ = ('excess_bytes',)
    wire_type = Blob.wire_type

    def __init__(self, fields=(), *, indexed=False, excess_bytes=0):
        super().__init__(fields, indexed=indexed)
        self.excess_bytes = excess_bytes

    def _pretty_extra_post(self):
        if self.excess_bytes:
            yield f', excess_bytes={self.excess_bytes}'

    def is_default(self):
        return not self.fields

    # This method intentionally has a different signature than super's.
    # noinspection PyMethodOverriding
    @classmethod
    def parse(cls, data, *, offset=0, indexed=False, field_id=None):
        try:
            length, length_bytes = read_varint(data, offset=offset)
        except ValueError as ex:
            raise ValueError(
                f'{ex.args[0]} while parsing length of {type(cls).__name__}'
            )
        excess_bytes = length_bytes - bytes_to_encode_varint(length)
        start = offset + length_bytes
        value = ProtoMessage.parse(
            data, offset=start, limit=start + length
        )
        return (
            cls(value, indexed=indexed, excess_bytes=excess_bytes),
            length_bytes + length
        )

    def byte_size(self):
        length = super().byte_size()
        return bytes_to_encode_varint(length) + self.excess_bytes + length

    def total_excess_bytes(self):
        return self.excess_bytes + super().total_excess_bytes()

    def strip_excess_bytes(self):
        self.excess_bytes = 0

    def iter_serialize(self):
        yield write_varint(super().byte_size(), excess_bytes=self.excess_bytes)
        yield from super().iter_serialize()

    def parse_submessage(self, *, parse_empty=False):
        return self

    def copy(self):
        clone = super().copy()
        # noinspection PyUnresolvedReferences,PyDunderSlots
        clone.excess_bytes = self.excess_bytes
        return clone
    __deepcopy__ = copy

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


# noinspection PyAbstractClass,PyMethodMayBeStatic
class _TagOnlyValue(_ProtoValue):
    __slots__ = ()

    def __repr__(self):
        return f'{type(self).__name__}()'

    def iter_pretty(self, indent, depth):
        yield repr(self)

    # noinspection PyUnusedLocal
    @classmethod
    def parse(cls, _data, *, offset=0, field_id=None):
        return cls(), 0

    def copy(self):
        return type(self)()  # There is no state in tag only values.
    __deepcopy__ = copy

    def is_default(self):
        return False

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


class Group(_FieldSet, _ProtoValue):
    __slots__ = ('excess_end_tag_bytes',)
    wire_type = GroupStart.wire_type
    delineator_type = GroupEnd

    def __init__(self, fields=(), *, indexed=False, excess_end_tag_bytes=0):
        super().__init__(fields, indexed=indexed)
        self.excess_end_tag_bytes = excess_end_tag_bytes

    def __repr__(self):
        if self.excess_end_tag_bytes:
            return (
                f'{type(self).__name__}('
                f'{repr(self.fields)}, '
                f'excess_end_tag_bytes={repr(self.excess_end_tag_bytes)}'
                f')'
            )
        else:
            return f'{type(self).__name__}({repr(self.fields)})'

    def _pretty_extra_post(self):
        if self.excess_end_tag_bytes:
            yield f', excess_end_tag_bytes={repr(self.excess_end_tag_bytes)}'

    def copy(self):
        clone = super().copy()
        # noinspection PyUnresolvedReferences,PyDunderSlots
        clone.excess_end_tag_bytes = self.excess_end_tag_bytes
        return clone
    __deepcopy__ = copy

    def parse_submessage(self, *, parse_empty=False):
        raise TypeError('Groups cannot be parsed further')

    def unparse(self):
        raise TypeError('Groups cannot be unparsed')

    def is_default(self):
        return False

    def total_excess_bytes(self):
        return (
                super().total_excess_bytes() +
                self.excess_end_tag_bytes
        )

    def delineator_size(self, field_id):
        return bytes_to_encode_tag(field_id) + self.excess_end_tag_bytes

    def delineator_iter_serialize(self, field_id):
        return Field(
            field_id,
            self.delineator_type(),
            excess_tag_bytes=self.excess_end_tag_bytes
        ).iter_serialize()

    def strip_excess_bytes(self):
        super().strip_excess_bytes()
        self.excess_end_tag_bytes = 0


# Mapping from wire type to value klass.
WIRE_TYPE_KLASSES = {
    klass.wire_type: klass
    for klass in [
        Varint,
        Fixed8Bytes,
        Blob,
        Group,
        GroupEnd,
        Fixed4Bytes,
    ]
}
WIRE_TYPE_KLASSES_EXPLICIT_GROUP = {
    **WIRE_TYPE_KLASSES,
    GroupStart.wire_type: GroupStart,
}

# These are all the types that will appear in repr strings. We don't need to
# include any other utility functions, but it's important that the user can
# import * and not get repr values that can't eval back to an equivalent object.
__all__ = (
    'ProtoMessage',
    'Field',
    'Varint',
    'Blob',
    'Fixed4Bytes',
    'Fixed8Bytes',
    'PackedRepeated',
    'SubMessage',
    'Group',
    'GroupStart',
    'GroupEnd',
)
