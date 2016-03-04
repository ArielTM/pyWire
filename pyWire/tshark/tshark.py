"""
Module used for the actual running of TShark
"""
import os
import subprocess
import sys

class TSharkNotFoundException(Exception):
    pass

def get_tshark_path():
    """
    Finds the path of the tshark executable. default locations will be searched.
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    if sys.platform.startswith('win'):
        win32_progs = os.environ.get('ProgramFiles(x86)', '')
        win64_progs = os.environ.get('ProgramW6432', '')
        tshark_path = ('Wireshark', 'tshark.exe')
        possible_paths = [os.path.join(win32_progs, *tshark_path),
                          os.path.join(win64_progs, *tshark_path)]
    else:
        possible_paths = ['/usr/bin/tshark',
                          '/usr/sbin/tshark',
                          '/usr/lib/tshark',
                          '/usr/local/bin/tshark']
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException('TShark not found in the following locations: ' + ', '.join(possible_paths) +
                                  ' Either place tshark there or add more paths to this file.')

def get_tshark_version():
    parameters = [get_tshark_path(), '-v']
    
    # this one works only in 2.7
    # version_output = subprocess.check_output(parameters).decode("ascii")
    version_output = subprocess.Popen(parameters, stdout=subprocess.PIPE).communicate()[0].decode("ascii")
    
    version_line = version_output.splitlines()[0]
    version_string = version_line.split()[1]

    return version_string

def get_tshark_interfaces():
    parameters = [get_tshark_path(), '-D']
    # this one works only in 2.7
    # tshark_interfaces = subprocess.check_output(parameters).decode("ascii")
    tshark_interfaces = subprocess.Popen(parameters , stdout=subprocess.PIPE).communicate()[0].decode("ascii")
    return tshark_interfaces.splitlines()
    # return [line.split('.')[0] for line in tshark_interfaces.splitlines()]
