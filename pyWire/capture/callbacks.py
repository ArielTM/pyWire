class Callback(object):
    @staticmethod
    def CB_PrintPacket(pkt , args = None):
        '''
        This callback will print the packet in Wireshark format.
        '''
        print pkt
    @staticmethod
    def CB_PrintReprPacket(pkt , args = None):
        '''
        This callback will print the packet in summarized format.
        '''
        print repr(pkt)

    @staticmethod
    def CB_AddPacketToList(pkt , args):
        '''
        This callback will save the packets in a list
        '''
        packetList = args
        packetList.append(pkt)
    
    @staticmethod
    def CB_SaveToPcapFile(pkt , args):
        '''
        This callback will save the packets in a PCAP file.
        args should be a PCAP file object
        '''
        args.WritePacket(pkt)
        