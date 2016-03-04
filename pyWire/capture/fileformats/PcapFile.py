import struct
import os

class PcapFile(object):
    # see wiki.wiresharl.org/Development/LibpcapFileFormat
    GLOBAL_HEADER = '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'
    GLOBAL_HEADER_SIZE = len(GLOBAL_HEADER)
    PACKET_HEADER_SIZE = 4*4
    '''
        Global Header:
            DWORD   magic       \xd4\xc3\xb2\xa1
            WORD    majorV      \x02\x00
            WORD    minorV      \x04\x00
            DWORD   thiszone    \x00\x00\x00\x00    GMT to local correction
            DWORD   sigfigs     \x00\x00\x00\x00    accuracy of timestamps
            DWORD   snaplen     \xff\xff\x00\x00    max length of captured packets saved in bytes (larger will be truncated)
            DWORD   network     \x01\x00\x00\x00    data link type
    '''
    
    def __init__(self , path):
        self._path = path
        self._handle = None
    
    def WritePacket(self , thePacket):
        sec =  thePacket.sniff_timestamp.split('.')[0]
        microSec = thePacket.sniff_time.microsecond
        self._WritePacket( thePacket.GetRaw(),int(sec) , microSec)
    
    def _WritePacket(self , packetData , timestampSec , timestampMicrosec):
        '''
            Each packet has:
            packet header:
                DWORD   ts_sec      timestamp seconds
                DWORD   ts_usec     timestamp microseconds
                DWORD   incl_len    number of bytes of packet saved (if smaller then orig_len, packet was truncated)
                DWORD   orig_len    actual length of packet
            packet data:
                incl_len    bytes
        '''
        if self._handle is None:
            self._Open('wb')
            self._handle.write(PcapFile.GLOBAL_HEADER)

        packetBuffer = ''
        lenData = len(packetData)
        if lenData > 0xffff:
            raise Exception('Could not save whole packet, too big')
        packetBuffer += struct.pack('IIII',timestampSec,timestampMicrosec,lenData,lenData)
        packetBuffer += packetData
        
        self._handle.write(packetBuffer)
        
    def Close(self):
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        
    def ReadPackets(self):
        self._Open()
        # read and parse global header
        self._ParseGlobalHeader(self._handle.read(self.GLOBAL_HEADER_SIZE))
        
        # read packet header
        packetHeader = self._handle.read(PcapFile.PACKET_HEADER_SIZE)
        while (packetHeader is not None) and (packetHeader != ''):
            timestampSec,timestampMicrosec,lenData,origLenData = self._ParsePacketHeader(packetHeader)
            packetData = self._handle.read(lenData)
            yield RawPacket(packetData , timestampSec,timestampMicrosec,lenData,origLenData)
            
            # next packet header
            packetHeader = self._handle.read(PcapFile.PACKET_HEADER_SIZE)
            
        self.Close()

    def _Open(self , mode = 'rb'):
        if self._handle is not None:
            raise Exception('Trying to open while already open!')
            
        if type(self._path) is str: # path to file
            self._handle = open(self._path , mode)
        elif type(self._path) is int: # file or pipe descriptor
            self._handle = os.fdopen(self._path , mode)
        else:
            self._handle = self._path
        #else:
        #    raise Exception('Unsupported descriptor was given')

    def _ParseGlobalHeader(self, theHeader):
        magic = theHeader[:4]
        theHeader = theHeader[4:]
        # the magic dictates if file written in little or big endian
        if magic == '\xd4\xc3\xb2\xa1':
            self._littleEndian = True
            self._endian = '<'
        elif magic == '\xa1\xb2\xc3\xd4':
            self._littleEndian = False
            self._endian = '>'
        else:
            raise Exception('Not a pcap file!')
            
        format = self._endian + 'HHIIII'
        majorV, minorV, thiszone, sigfigs, snaplen, network = struct.unpack(format,theHeader)
        self._version = (majorV, minorV)
        self._zone = thiszone
        self._sigfigs = sigfigs
        self._snaplen = snaplen
        self._network = network
        
    def _ParsePacketHeader(self , thePacketHeader):
        format = self._endian + 'IIII'
        timestampSec,timestampMicrosec,lenData,origLenData = struct.unpack(format,thePacketHeader)
        return (timestampSec,timestampMicrosec,lenData,origLenData)
    
    
    
class RawPacket(object):
    def __init__(self , packetData , timestampSec,timestampMicrosec,lenData,origLenData):
        self.raw = packetData
        self.captureTimestampSec = timestampSec
        self.captureTimestampMicrosec = timestampMicrosec
        self.lenData = lenData
        self.origLenData = origLenData