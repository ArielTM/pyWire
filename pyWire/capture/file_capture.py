from pyWire.capture.capture import Capture, PacketsSource
from pyWire.capture.fileformats.PcapFile import PcapFile

class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, display_filter=None, 
                 decryption_key=None, encryption_type='wpa-pwk'):
        """
        Creates a packet capture object by reading from file.

        :param keep_packets: Whether to keep packets after reading them via next(). Used to conserve memory when reading
        large caps (can only be used along with the "lazy" option!)
        :param input_file: File path of the capture (PCAP, PCAPNG)
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information.
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        """
        super(FileCapture, self).__init__(display_filter=display_filter,
                                          decryption_key=decryption_key, encryption_type=encryption_type)
        self.input_filename = input_file
        if not isinstance(input_file, basestring):
            self.input_filename = input_file.name

    def GetPacketsSource(self):
        '''
        This function should return PacketsSource object, which should implement:
            GetPacketsFeeder
            StartPacketsSource
            GetNextRawPacket
            ClosePacketsSource
        '''
        return FilePacketsSource(self.input_filename)
            
    # def get_parameters(self):
        # return super(FileCapture, self).get_parameters(packet_count=packet_count) + ['-r', self.input_filename]

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.input_filename)
        
class FilePacketsSource(PacketsSource):
    def __init__(self , pcapFilePath):
        self.pcapFilePath = pcapFilePath
        self._feeder = None
        self._pcapFile = None
        
    def StartPacketsSource(self):
        self._feeder = open(self.pcapFilePath , 'rb')
        self._pcapFile = PcapFile(self.pcapFilePath)
        self._pktGen = self._pcapFile.ReadPackets()
        self._curPktNum = 0
        
    def GetNextRawPacket(self , packetNumber = None):
        if packetNumber is None:
            self._curPktNum += 1
            return self._pktGen.next().raw
        else:
            while self._curPktNum < packetNumber:
                curRawPkt = self._pktGen.next().raw
                self._curPktNum += 1
            return curRawPkt
        
    def ClosePacketsSource(self):
        if self._feeder:
            self._feeder.close()
            self._feeder = None
        if self._pcapFile:
            self._pcapFile.Close()
            self._pcapFile = None