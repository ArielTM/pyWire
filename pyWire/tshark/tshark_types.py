import time


def string_converter(val):
    return val

def int_converter(val):
    return int(val, base=16)


def float_converter(val):
    return float(val)


def bool_converter(val):
    if int(val) > 0:
        return True
    else:
        return False


def date_converter(val):
    return time.gmtime(float(val))


TSHARK_TYPES = {
    "FT_NONE":			string_converter,
    "FT_PROTOCOL":		string_converter,
    "FT_BOOLEAN":		bool_converter,
    "FT_UINT8":			int_converter,
    "FT_UINT16":		int_converter,
    "FT_UINT24":		int_converter,
    "FT_UINT32":		int_converter,
    "FT_UINT40":		int_converter,
    "FT_UINT48":		int_converter,
    "FT_UINT56":		int_converter,
    "FT_UINT64":		int_converter,
    "FT_INT8":			int_converter,
    "FT_INT16":			int_converter,
    "FT_INT24":			int_converter,
    "FT_INT32":			int_converter,
    "FT_INT40":			int_converter,
    "FT_INT48":			int_converter,
    "FT_INT56":			int_converter,
    "FT_INT64":			int_converter,
    "FT_FLOAT":			float_converter,
    "FT_DOUBLE":		float_converter,
    "FT_ABSOLUTE_TIME":	date_converter,
    "FT_RELATIVE_TIME":	date_converter,
    "FT_STRING":		string_converter,
    "FT_STRINGZ":		string_converter,
    "FT_UINT_STRING":	string_converter,
    "FT_ETHER":			string_converter,
    "FT_BYTES":			string_converter,
    "FT_UINT_BYTES":	string_converter,
    "FT_IPv4":			string_converter,
    "FT_IPv6":			string_converter,
    "FT_IPXNET":		string_converter,
    "FT_FRAMENUM":		string_converter,
    "FT_PCRE":			string_converter,
    "FT_GUID":			string_converter,
    "FT_OID":			string_converter,
    "FT_EUI64":			string_converter,
    "FT_AX25":			string_converter,
    "FT_VINES":			string_converter,
    "FT_REL_OID":		string_converter,
    "FT_SYSTEM_ID":		string_converter,
    "FT_STRINGZPAD":	string_converter,
    "FT_FCWWN":			string_converter,
}