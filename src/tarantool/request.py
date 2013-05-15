# -*- coding: utf-8 -*-
# pylint: disable=C0301,W0105,W0401,W0614
'''
Request types definitions
'''

import struct

from tarantool.const import *
from tarantool.types import *


class Request(object):
    '''\
    Represents a single request to the server in compliance with the Tarantool protocol.
    Responsible for data encapsulation and builds binary packet to be sent to the server.

    This is the abstract base class. Specific request types are implemented by the inherited classes.
    '''
    request_type = None

    # Pre-generated results of pack_int_base128() for small arguments (0..16383)
    _int_base128 = tuple(
        (
            struct_B.pack(val) if val < 128 else struct_BB.pack(val >> 7 & 0xff | 0x80, val & 0x7F) \
            for val in xrange(0x4000)
        )
    )

    def __init__(self):
        self._bytes = None
        raise NotImplementedError("Abstract method must be overridden")


    def __bytes__(self):
        return self._bytes
    __str__ = __bytes__


    @classmethod
    def header(cls, body_length):
        return struct_LLL.pack(cls.request_type, body_length, 0)


    @staticmethod
    def pack_int(value):
        '''\
        Pack integer field
        <field> ::= <int32_varint><data>

        :param value: integer value to be packed
        :type value: int

        :return: packed value
        :rtype: bytes
        '''
        if __debug__:
            if not isinstance(value, int):
                raise TypeError("Invalid argument type '%s'. Only 'int' expected"%type(value).__name__)
            if value < 0:
                raise TypeError("Number %d does not fit into NUM32 type"%value)
        return struct_BL.pack(4, value)

    @staticmethod
    def pack_int64(value):
        '''\
        Pack integer64 field
        <field> ::= <int32_varint><data>

        :param value: integer value to be packed
        :type value: int

        :return: packed value
        :rtype: bytes
        '''
        if __debug__:
            if not isinstance(value, (int, long)):
                raise TypeError("Invalid argument type '%s'. Only 'int' or 'long' expected"%type(value).__name__)
            if (value < 0) or (value > 18446744073709551615):
                raise TypeError("Number %d does not fit into NUM64 type"%value)
        return struct_BQ.pack(8, value)


    @classmethod
    def pack_int_base128(cls, value):
        '''\
        Pack integer value using LEB128 encoding
        :param value: integer value to encode
        :type value: int

        :return: encoded value
        :rtype: bytes
        '''

        if value < 1 << 14:
            return cls._int_base128[value]

        if value < 1 << 21:
            return struct_BBB.pack(
                        value >> 14 & 0xff | 0x80,
                        value >> 7 & 0xff | 0x80,
                        value & 0x7F
            )

        if value < 1 << 28:
            return struct_BBBB.pack(
                        value >> 21 & 0xff | 0x80,
                        value >> 14 & 0xff | 0x80,
                        value >> 7 & 0xff | 0x80,
                        value & 0x7F
            )

        if value < 1 << 35:
            return struct_BBBBB.pack(
                        value >> 28 & 0xff | 0x80,
                        value >> 21 & 0xff | 0x80,
                        value >> 14 & 0xff | 0x80,
                        value >> 7 & 0xff | 0x80,
                        value & 0x7F
            )

        raise OverflowError("Number too large to be packed")


    @classmethod
    def pack_str(cls, value):
        '''\
        Pack string field
        <field> ::= <int32_varint><data>

        :param value: string to be packed
        :type value: bytes or str

        :return: packed value
        :rtype: bytes
        '''
        if __debug__:
            if not isinstance(value, basestring):
                raise TypeError("Invalid argument type '%s', 'str' expected"%type(value).__name__)
        value_len_packed = cls.pack_int_base128(len(value))
        return struct.pack("<%ds%ds"%(len(value_len_packed), len(value)), value_len_packed,  value)


    @classmethod
    def pack_field(cls, value, cast_to = None):
        '''\
        Pack single field (string or integer value)
        <field> ::= <int32_varint><data>

        :param value: value to be packed
        :type value: bytes, str or int

        :return: packed value
        :rtype: bytes
        '''
        if cast_to:
            if cast_to in (NUM, int):
                return cls.pack_int(value)
            elif cast_to in (STR, RAW, basestring, bytes, None):
                return cls.pack_str(value)
            elif cast_to in (NUM64, long):
                return cls.pack_int64(value)
            else:
                raise TypeError("Invalid field type %d."%cast_to)
        else:
            # try to autodetect tarantool types based on python types
            if isinstance(value, basestring):
                return cls.pack_str(value)
            elif isinstance(value, int):
                if value > 4294967295:
                    return cls.pack_int64(value)
                else:
                    return cls.pack_int(value)
            elif isinstance(value, long):
                return cls.pack_int64(value)
            else:
                raise TypeError("Invalid argument type '%s'. Only 'str', 'int' or 'long' expected"%type(value).__name__)


    @classmethod
    def pack_tuple(cls, values, space_def = None):
        '''\
        Pack tuple of values
        <tuple> ::= <cardinality><field>+

        :param value: tuple to be packed
        :type value: tuple of scalar values (bytes, str or int)

        :return: packed tuple
        :rtype: bytes
        '''
        assert isinstance(values, (tuple, list))
        cardinality = struct_L.pack(len(values))
        packed_items = []
        packed_items.append(cardinality)

        if space_def:
            field_defs = space_def['fields']
            default_type = space_def['default_type']
            for field_no, value in enumerate(values):
                (_name, dtype) = field_defs.get(field_no, (None, default_type))
                packed_items.append(cls.pack_field(value, dtype))
        else:
            for value in values:
                packed_items.append(cls.pack_field(value))

        return b"".join(packed_items)


    @classmethod
    def pack_key(cls, values, space_def = None, index_no = None):
        '''\
        Pack key tuple
        <tuple> ::= <cardinality><field>+

        :param value: key tuple to be packed
        :type value: tuple of scalar values (bytes, str or int)

        :return: packed tuple
        :rtype: bytes
        '''
        assert isinstance(values, (tuple, list))
        cardinality = struct_L.pack(len(values))
        packed_items = []
        packed_items.append(cardinality)

        if space_def:
            assert index_no is not None
            field_defs = space_def['fields']
            (_index_name, indexed_fields) = space_def['indexes'][index_no]
            assert isinstance (indexed_fields, list)
            for part, value in enumerate(values):
                field_no = indexed_fields[part]
                # field types must be defined for indexed fields
                (_name, dtype) = field_defs[field_no]
                packed_items.append(cls.pack_field(value, dtype))
        else:
            for value in values:
                packed_items.append(cls.pack_field(value))

        return b"".join(packed_items)



class RequestInsert(Request):
    '''\
    Represents INSERT request

    <insert_request_body> ::= <space_no><flags><tuple>
    |--------------- header ----------------|--------- body ---------|
     <request_type><body_length><request_id> <space_no><flags><tuple>
                                                               |
                          items to add (multiple values)  -----+
    '''
    request_type = REQUEST_TYPE_INSERT

    def __init__(self, space_no, values, return_tuple, space_def): # pylint: disable=W0231
        '''\
        '''
        assert isinstance(values, (tuple, list))
        flags = 1 if return_tuple else 0

        request_body = \
            struct_LL.pack(space_no, flags) + \
            self.pack_tuple(values, space_def)

        self._bytes = self.header(len(request_body)) + request_body



class RequestDelete(Request):
    '''
    Represents DELETE request

    <delete_request_body> ::= <space_no><flags><tuple>
    |--------------- header ----------------|--------- body ---------|
     <request_type><body_length><request_id> <space_no><flags><tuple>
                                                               |
                          key to search in primary index  -----+
                          (tuple with single value)
    '''
    request_type = REQUEST_TYPE_DELETE

    def __init__(self, space_no, key, return_tuple, space_def):    # pylint: disable=W0231
        '''
        '''
        flags = 1 if return_tuple else 0

        request_body = \
            struct_LL.pack(space_no, flags) + \
            self.pack_key((key,), space_def, 0)

        self._bytes = self.header(len(request_body)) + request_body


class RequestSelect(Request):
    '''\
    Represents SELECT request

    <select_request_body> ::= <space_no><index_no><offset><limit><count><tuple>+

    |--------------- header ----------------|---------------request_body ---------------------...|
     <request_type><body_length><request_id> <space_no><index_no><offset><limit><count><tuple>+
                                                        ^^^^^^^^                 ^^^^^^^^^^^^
                                                            |                          |
                                           Index to use ----+                          |
                                                                                       |
                            List of tuples to search in the index ---------------------+
                            (tuple cardinality can be > 1 when using composite indexes)
    '''
    request_type = REQUEST_TYPE_SELECT

    def __init__(self, space_no, index_no, tuple_list, offset, limit, space_def):    # pylint: disable=W0231

        assert isinstance(tuple_list, (list, tuple))

        request_body = \
            struct_LLLLL.pack(space_no, index_no, offset, limit, len(tuple_list)) + \
            b"".join([self.pack_key(t, space_def, index_no) for t in tuple_list])

        self._bytes = self.header(len(request_body)) + request_body



class RequestUpdate(Request):
    '''
    <update_request_body> ::= <space_no><flags><tuple><count><operation>+
    <operation> ::= <field_no><op_code><op_arg>

    |--------------- header ----------------|---------------request_body --------------...|
     <request_type><body_length><request_id> <space_no><flags><tuple><count><operation>+
                                                               |      |      |
                           Key to search in primary index -----+      |      +-- list of operations
                           (tuple with cardinality=1)                 +-- number of operations
    '''

    request_type = REQUEST_TYPE_UPDATE

    def __init__(self, space_no, key, op_list, return_tuple, space_def):    # pylint: disable=W0231
        flags = 1 if return_tuple else 0
        assert isinstance(key, (int, basestring))

        request_body = \
            struct_LL.pack(space_no, flags) + \
            self.pack_key((key,), space_def, 0) + \
            struct_L.pack(len(op_list)) +\
            self.pack_operations(op_list)

        self._bytes = self.header(len(request_body)) + request_body

    @classmethod
    def pack_operations(cls, op_list):
        result = []
        for op in op_list:
            try:
                field_no, op_symbol, op_arg = op
            except ValueError:
                raise ValueError("Operation must be a tuple of 3 elements (field_id, op, value)")
            try:
                op_code = UPDATE_OPERATION_CODE[op_symbol]
            except KeyError:
                raise ValueError("Invalid operaction symbol '%s', expected one of %s"\
                                %(op_symbol, ', '.join(["'%s'"%c for c in sorted(UPDATE_OPERATION_CODE.keys())])))
            data = b"".join([struct_LB.pack(field_no, op_code), cls.pack_field(op_arg)])
            result.append(data)
        return b"".join(result)



class RequestCall(Request):
    '''
    <call_request_body> ::= <flags><proc_name><tuple>
    <proc_name> ::= <field>

    |--------------- header ----------------|-----request_body -------|
     <request_type><body_length><request_id> <flags><proc_name><tuple>
                                                                |
                                    Lua function arguments -----+
    '''
    request_type = REQUEST_TYPE_CALL

    def __init__(self, proc_name, args, return_tuple):    # pylint: disable=W0231
        flags = 1 if return_tuple else 0
        assert isinstance(args, (list, tuple))

        request_body = \
            struct_L.pack(flags) + \
            self.pack_field(proc_name, STR) +\
            self.pack_tuple([k for k in args])

        self._bytes = self.header(len(request_body)) + request_body
