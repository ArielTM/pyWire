'''
    pyWire
    
    Pythonic interface for sniffing with Wireshark.
    
    Usage:
        step 1: create one of the following capture object.
            myCap= pyWire.LiveCapture- create live capture on local interface(s)
            myCap= pyWire.FileCapture- create capture from pcap file.
            myCap= pyWire.InMemCapture- create capture from given packet list. 
        
        step 2: define callback to process packets
            def myCallback(pkt , args):
                # do stuff here
                # NOTE: Read help(pyWire.packet) to understand packet objects.
                
            Note: you may also use predefined callbacks from pyWire.Callback
        
        step 3: start sniffing and processing packets
            myCap.apply_on_packets(myCallback , args = myArguments)
        
    Capture options:
        Live captures can have a capture filter in bpf format.
        only packets that match the bpf will be captured.
        
        Both live and File captures can have display filter (wireshark format)
        only packets the pass the display filter will be passed to the callback.
        
        apply_on_packets can receive optional arguments to limit the sniffer:
            timeout - limit amount of time to sniff (seconds).
            packet_count - limit number of packets to capture.
        
    More stuff:
        pyWire.PcapFile
            Create, Read and Write Pcap files.
            You can save packets from your capture in pcap files.
        
        pyWire.LiveCapture.GetInterfaces()
            Return a list of local available interfaces.
            You can sniff on those interfaces, referencing them by their number.
        
        pyWire.GetSamplePackets()
            Quick way to get list of packet object for testing.
        
        pyWire.InMemFilterPackets
            Filter a given list of packets using a display filter.
            Return the filtered list.
'''


from pyWire.capture.fileformats.PcapFile import PcapFile
from pyWire.capture.live_capture import LiveCapture, GetSamplePackets
from pyWire.capture.file_capture import FileCapture
from pyWire.capture.callbacks import Callback
from pyWire.capture.inmem_capture import InMemCapture, InMemFilterPackets

####
# Not implemented Yet
####
#from pyWire.capture.remote_capture import RemoteCapture
