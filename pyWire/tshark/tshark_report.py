"""
This module parses generated Tshark reports
"""

import subprocess
from pyWire.tshark.tshark import get_tshark_path
from pyWire.tshark.tshark_types import TSHARK_TYPES, int_converter, date_converter, string_converter

def parse_tshark_fields():
    parameters = [get_tshark_path(), '-G', 'fields']

    tshark_process = subprocess.Popen(parameters,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)

    if tshark_process.returncode is not None and self.tshark_process.returncode != 0:
        raise Exception(
            'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))

    fields_type = {}

    while True:
        field_line = tshark_process.stdout.readline()
        if field_line == '':
            break

        # parsing according to https://www.wireshark.org/docs/man-pages/tshark.html

        if not field_line.startswith('F\t'):
            continue

        fields = field_line.split('\t')
        fields_type[fields[2]] = TSHARK_TYPES[fields[3]]

    fields_type["num"] = int_converter
    fields_type["len"] = int_converter
    fields_type["caplen"] = int_converter
    fields_type["timestamp"] = date_converter
    fields_type["data"] = string_converter

    return fields_type
