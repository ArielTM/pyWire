from pyWire.capture.capture import Capture,PacketsSource,TSharkCrashException
from pyWire.tshark.tshark import get_tshark_interfaces, get_tshark_path
from pyWire.capture.fileformats.PcapFile import PcapFile
from pyWire.capture.callbacks import Callback

import os
import subprocess
from threading import Thread

# patch for pipe problem when using display_filter
from bigPipe import bigPipe

class LiveCapture(Capture):
    """
    Represents a live capture on a network interface.
    """

    def __init__(self, interface=None, bpf_filter=None, display_filter=None, decryption_key=None,
                 encryption_type='wpa-pwk'):
        """
        Creates a new live capturer on a given interface. Does not start the actual capture itself.

        :param interface: Name of the interface to sniff on. If not given, takes the first available.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        """
        super(LiveCapture, self).__init__(display_filter=display_filter, decryption_key=decryption_key, encryption_type=encryption_type)
        self.bpf_filter = bpf_filter
        
        if interface is None:
            interfacesList = get_tshark_interfaces()
            self.interfaces = [line.split('.')[0] for line in interfacesList]
        else:
            if type(interface) is list:
                self.interfaces = interface
            else:
                self.interfaces = [interface]
        # BUG
        # dump cap write to standard output in PCAPNG format when capturing from multiple interfaces
        # tshark can only read pcap format from standard input.
        if len(self.interfaces) > 1:
            raise NotImplementedError("Capturing from multiple interfaces doesn't work currently, sorry!")
       
       
    @staticmethod
    def GetInterfaces():
        return get_tshark_interfaces()

    def GetPacketsSource(self):
        '''
        This function should return PacketsSource object, which should implement:
            GetPacketsFeeder
            StartPacketsSource
            GetNextRawPacket
            ClosePacketsSource
        '''
        return LivePacketsSource(self.interfaces , self.bpf_filter , self._packet_count , self._timeout)
        
class LivePacketsSource(PacketsSource):
    _BATCH_SIZE = 4096
    _MAX_INTERNAL_BUFFER = 4096*5000 # 200M
    def __init__(self , interfaces , bpf_filter , packetCount , timeout):
        self._interfaces = interfaces
        self._bpf_filter = bpf_filter
        
        self._packet_count = packetCount
        self._timeout = timeout
        
        self._feeder = None
        self._dumpcap_process = None
        
    def StartPacketsSource(self):
        self._dumpcap_process = self._GetDumpcapProcess()
        self._distributeThread = self._StartDistributeThread()
        self._distributeThread.start()
        
        self._feeder = os.fdopen(self._tsharkFeeder,'rb')
        self._pcapFile = PcapFile(self._pcapFeeder)
        self._pktGen = self._pcapFile.ReadPackets()
        self._curPktNum = 0
    
    def _StartDistributeThread(self):
        source = self._dumpcap_process.stdout
        self._tsharkFeeder , input1 = os.pipe()
        #self._pcapFeeder , input2 = os.pipe()
        
        ##########  patch for using display filter, because pipe may fill before relevant packet arrive
        self._pcapFeeder = bigPipe(LivePacketsSource._MAX_INTERNAL_BUFFER)
        input2 = self._pcapFeeder
        ##########
        
        args = (source, input1 , input2)
        return Thread(target = LivePacketsSource._DistributeWorker , args = args)
    
    @staticmethod
    def _DistributeWorker(source, input1 , input2):
        '''
        This thread takes input from a single pipe, and copy it to two pipes.
        '''
        data = source.read(LivePacketsSource._BATCH_SIZE)
        while data is not None and data != '':
            os.write(input1 , data)
            #os.write(input2 , data)
            input2.write(data)

            data = source.read(LivePacketsSource._BATCH_SIZE)

        # thread will exit when the source is closed
        os.close(input1)    # will stop thsark feed
        #os.close(input2)    # will stop the pcap object feed
        pass
    
    def _GetDumpcapProcess(self):
        tsharkPath = get_tshark_path()
        wiresharkDir = os.path.dirname(tsharkPath)
        thsarkBinName = os.path.basename(tsharkPath)
        dumpcapBinName = thsarkBinName.replace('tshark','dumpcap')
        dumpcapPath = os.path.join(wiresharkDir , dumpcapBinName)
        parameters = [dumpcapPath, '-P', '-q' , '-t' , '-w' , '-']
        # -P = pcap format, -q = dont print packet counts, -t = use thread per interface
        # -w - = write to standard output
        
        if self._packet_count:
            parameters += ['-c', str(self._packet_count)]
        if self._timeout:
            parameters += ['-a', 'duration:' + str(self._timeout)]
        if self._bpf_filter:
            parameters += ['-f' , self._bpf_filter]
        if self._interfaces:
            for iface in self._interfaces:
                parameters += ['-i' , iface]
        
        print parameters
        dumpcap_process = subprocess.Popen(parameters , 
                            stdout = subprocess.PIPE, 
                            stderr = subprocess.PIPE)

        if dumpcap_process.returncode is not None and self.dumpcap_process.returncode != 0:
            raise TSharkCrashException(
                'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
        return dumpcap_process
        
        
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
        if self._dumpcap_process:
            self._dumpcap_process.kill()
            retCode = self._dumpcap_process.wait()
            self._outputText = self._dumpcap_process.stderr.read()
            print self._outputText

def GetSamplePackets(interface = '1' , timeout = 10 , packet_count = 50):
    pktList = []
    cap = LiveCapture(interface)
    cap.apply_on_packets(Callback.CB_AddPacketToList , args = pktList, timeout = timeout , packet_count = packet_count )
    return pktList