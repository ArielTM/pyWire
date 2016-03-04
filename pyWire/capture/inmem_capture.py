import time
import tempfile
import os

from pyWire.packet.packet import Packet
from pyWire.capture.file_capture import FileCapture
from pyWire.capture.fileformats.PcapFile import PcapFile
from pyWire.capture.callbacks import Callback

class LinkTypes(object):
    NULL = 0
    ETHERNET = 1
    IEEE802_5 = 6
    PPP = 9
    IEEE802_11 = 105

class InMemCapture(FileCapture):
    """"
    A class representing a capture read from memory - list of packets.
    It does use temporary file though.
    """
    def __init__(self, packet_list, display_filter=None,
                  decryption_key=None, encryption_type='wpa-pwk'):
        """
        Creates a new in-mem capture, a capture capable of receiving binary packets and parsing them using tshark.
        Currently opens a new instance of tshark for every packet buffer,
        so it is very slow -- try inserting more than one packet at a time if possible.
        
        :param packet_list: The packets list. May contain packet objects or raw bytes of packets as strings.
        :param display_filter: Display (wireshark) filter to use.
        :param decryption_key: Key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD',
        or 'WPA-PWK'. Defaults to WPA-PWK).
        """
        theTmpFile = tempfile.NamedTemporaryFile(prefix = 'pyWire_InMem_tmp_')
        self.tmpFileName = theTmpFile.name
        del(theTmpFile)
        thePcapFile = PcapFile(self.tmpFileName)
        for i , pkt in enumerate(packet_list):
            if type(pkt) == Packet:
                thePcapFile.WritePacket(pkt)
            elif type(pkt) == str:
                curTime = time.time()
                thePcapFile._WritePacket(pkt , int(curTime) , curTime-int(curTime))
            else:
                print 'Warning, skipping %d packet - unknown format' % i
        thePcapFile.Close()
        super(InMemCapture, self).__init__( input_file = self.tmpFileName , display_filter=display_filter,
                                           decryption_key=decryption_key, encryption_type=encryption_type)
    
    def __del__(self):
        os.remove(self.tmpFileName)
        
def InMemFilterPackets(pktList , display_filter):
    '''
        Filter the given packet list using the given display filter.
        Return a new list with the filtered packets.
    '''
    cap = InMemCapture(pktList , display_filter)
    newList = []
    cap.apply_on_packets(Callback.CB_AddPacketToList , args = newList)
    del(cap)
    return newList