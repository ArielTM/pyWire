# most of the code here is from pyshark\Capture\capture.py
import subprocess

from pyWire.tshark.tshark import get_tshark_path, get_tshark_version
from pyWire.tshark.tshark_xml import packet_from_xml_packet
from pyWire.tshark.tshark_report import parse_tshark_fields
# for getting version of tshark
from distutils.version import LooseVersion

class Capture(object):
    """
    Base class for packet captures.
    """
    DEFAULT_BATCH_SIZE = 4096
    SUPPORTED_ENCRYPTION_STANDARDS = ['wep', 'wpa-pwk', 'wpa-psk']
    
    def __init__(self, display_filter=None, decryption_key=None, encryption_type='wpa-pwd'):
        '''
        initialize the capture object.
        '''
        self.display_filter = display_filter
        self.running_processes = set()
        self.fields_type = None

        if encryption_type and encryption_type.lower() in self.SUPPORTED_ENCRYPTION_STANDARDS:
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnknownEncyptionStandardException("Only the following standards are supported: %s."
                                                    % ', '.join(self.SUPPORTED_ENCRYPTION_STANDARDS))
        
    def apply_on_packets(self, packet_callback, timeout=None , packet_count = None ,args = None, parse_types=False):
        """
        Runs through all packets and calls the given callback (a function) with each one as it is read.
        If the capture is infinite (i.e. a live capture), it will run forever, otherwise it will complete after all
        packets have been read.

        Example usage:
        def print_callback(pkt):
            print pkt
        capture.apply_on_packets(print_callback)

        If a timeout is given, raises a Timeout error if not complete before the timeout (in seconds)
        """
        self._timeout = timeout
        self._packet_count = packet_count
        self._packetsSource = self.GetPacketsSource()
        
        self._packetsSource.StartPacketsSource()
        tshark_process = self._get_tshark_process()

        if parse_types:
            self.fields_type = parse_tshark_fields()
        
        try:
            self._go_through_packets_from_fd(tshark_process.stdout, packet_callback, args,
                                                        packet_count=packet_count)
        except:
            raise
        finally:
            self._cleanup_subprocess(tshark_process)
            print tshark_process.stderr.read()
            self._packetsSource.ClosePacketsSource()
            
    def GetPacketsSource(self):
        '''
        This function should return PacketsSource object, which should implement:
            GetPacketsFeeder
            StartPacketsSource
            GetNextRawPacket
            ClosePacketsSource
        '''
        raise NotImplementedError()
                    
    def _go_through_packets_from_fd(self, fd, packet_callback, args = None , packet_count=None):
        """
        A coroutine which goes through a stream and calls a given callback for each XML packet seen in it.
        """
        self.packets_captured = 0
        data = ''
        for packet, data in self._get_packet_from_stream(fd, data):
            if packet:
                self.packets_captured += 1
                packetNum = int(packet.geninfo.num.val_)
                packet.hasRaw = True
                packet.raw = self._packetsSource.GetNextRawPacket(packetNum)
                packet_callback(packet , args)

            if packet_count and self.packets_captured >= packet_count:
                break
    
    def _get_packet_from_stream(self, stream, existing_data):
        """
        A coroutine which returns a single packet if it can be read from the given StreamReader.
        :return a tuple of (packet, remaining_data). The packet will be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        while (True):
            # Read data until we get a packet, and yield it.
            new_data = stream.read(self.DEFAULT_BATCH_SIZE)
            if new_data == '':
                break
            existing_data += new_data
            packet, existing_data = self._extract_tag_from_data(existing_data)
            
            if packet:
                packet = packet_from_xml_packet(packet, self.fields_type)
                yield (packet, existing_data)
            else:
                yield (None, existing_data)

    @staticmethod
    def _extract_tag_from_data(data, tag_name='packet'):
        """
        Gets data containing a (part of) tshark xml.
        If the given tag is found in it, returns the tag data and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark xml.
        :return: a tuple of (tag, data). tag will be None if none is found.
        """
        opening_tag, closing_tag = b'<%s>' % tag_name, b'</%s>' % tag_name
        tag_end = data.find(closing_tag)
        if tag_end != -1:
            tag_end += len(closing_tag)
            tag_start = data.find(opening_tag)
            return data[tag_start:tag_end], data[tag_end:]
        return None, data
    
    def _get_tshark_process(self):
        """
        Returns a new tshark process with previously-set parameters.
        """
        parameters = [get_tshark_path(), '-T', 'pdml' ,'-i','-','-l'] + self.get_parameters()
        print parameters
        tshark_process = subprocess.Popen(parameters , 
                            stdin  = self._packetsSource.GetPacketsFeeder(),
                            stdout = subprocess.PIPE, 
                            stderr = subprocess.PIPE)

        if tshark_process.returncode is not None and self.tshark_process.returncode != 0:
            raise TSharkCrashException(
                'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
        self.running_processes.add(tshark_process)
        return tshark_process
        
    def get_parameters(self):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        tshark_version = get_tshark_version()
        if LooseVersion(tshark_version) >= LooseVersion("1.10.0"):
            display_filter_flag = '-Y'
        else:
            display_filter_flag = '-R'

        params = []
        if self.display_filter:
            params += [display_filter_flag, self.display_filter]
        if self._packet_count:
            params += ['-c', str(self._packet_count)]
        if self._timeout:
            params += ['-a', 'duration:' + str(self._timeout)]
        if all(self.encryption):
            params += ['-o', 'wlan.enable_decryption:TRUE', '-o', 'uat:80211_keys:"' + self.encryption[1] + ' ","' +
                                                                  self.encryption[0] + '"']
        return params
        
    def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected to it.
        """
        try:
            process.kill()
            retCode = process.wait()
        except:
            raise 
        #except ProcessLookupError:
        #    pass
        #except OSError:
        #    if os.name != 'nt':
        #        raise
       
class PacketsSource(object):
    def __init__(self):
        pass

    def GetPacketsFeeder(self):
        return self._feeder
        
    def StartPacketsSource(self):
        pass
        
    def GetNextRawPacket(self , packetNumber = None):
        raise NotImplementedError()
        
    def ClosePacketsSource(self):
        pass
       
class TSharkCrashException(Exception):
    pass

class UnknownEncyptionStandardException(Exception):
    pass
    
    
    
        
        