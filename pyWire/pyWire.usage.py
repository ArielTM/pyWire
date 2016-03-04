# to start, import pyWire
import pyWire


#########################
# Live Capture tutorial #
#########################
'''
 You can list the local interfaces by using the following code
'''
interfacesList = pyWire.LiveCapture.GetInterfaces()
for interfaceLine in interfacesList:
    print interfaceLine

'''
 in order to sniff on local interface, use pyWire.LiveCapture
  interface - number of the interface to capture on, as string. (eg '1')
              can also give list of interfaces, as list of strings (['1','3'])
              the number is the same as the one returned from pyWire.LiveCapture.GetInterfaces()
              default Capture on all interfaces.
  bpf_filter - capture filter as string. default None
  display_filter - display filter as string. default None
'''
interface = '1'
bpf_filter = 'tcp port 80'
display_filter = 'http.request.method == "GET"'
cap = pyWire.LiveCapture(interface , bpf_filter , display_filter)

#########################
# File Capture tutorial #
#########################

'''
 you can also open a pcap file instead, and read from it, use pyWire.FileCapture
  pcapFilePath - path to the pcap file
  display_filter - display filter as string. default None
'''
pcapFilePath = r'examplePcap.pcap'
display_filter = 'http.request.method == "GET"'
cap = pyWire.FileCapture(pcapFilePath, display_filter)

###########################
# Capture Object tutorial #
###########################

'''
 Either way, the capture object is now initialized.
 define a callback function, and call apply_on_packets
  callback - function that will be called for each packet. f(pkt , args)
  timeout - stop capture after X seconds. default None (forever)
  packet_count - stop capture after X packets. default None (forever)
  args - arguments for the callback function.
'''
def callback(pkt):
    print pkt
timeout = 5
packet_count = 100
args = '123'
cap.apply_on_packets(callback , timeout , packet_count , args)

####################
# Sample callbacks #
####################
'''
 You can use predefined callbacks from pyWire.Callback.<callback name>
 See the file callbacks.py for implementation
'''
# print full data for each packet, in wireshark format
pyWire.Callback.CB_PrintPacket
# print short description of each packet
pyWire.Callback.CB_PrintReprPacket
# add the packets to a list given as an argument
pyWire.Callback.CB_AddPacketToList

# usage example. myList will contain 5 packets
myList = []
cap.apply_on_packets(pyWire.Callback.CB_AddPacketToList , packet_count = 5, args = myList)

########################
# Working with packets #
########################
'''
 recall the example which return 5 packets in a list.
 we will use a packet object to demonstrate what you can do with it.
 In general, the packet object contains all data that you may find in Wireshark
'''
# packet object
# contains general info about the packet and layers objects.
pkt = myList[0]
pkt.layers          # list of layers object, from lower layer to top
pkt['UDP']          # will return the lowest layer with this name (if tunneled)
pkt[3]              # will return the 4th layer
pkt.transport_layer # the name of the transport layer of the packet
pkt.highest_layer   # the name of the top layer parsed
pkt.sniff_time      # datetime object, of when the packet was captured
pkt.sniff_timestamp # same, but in timestamp format
pkt.captured_length # length of packet that was captured

# layer object
# contains fields of the layer.
# the field name is usually the same as in wireshark, with the exception of illegal variable
# names, which is then replaced by underscore (_) or prepended by field_
# hidden fields start with _hid_
# NOTE: in case there are several fields with the same name, the field with this name
#       will be a List of field objects instead of a field object.
#       In protocols where its relevant, check wheter type(layer.field) is list or not.

udpLayer =  pkt['UDP']
udpLayer.dstport        # layer object of dstport

# field object
# contains the value of the field, as well as any sub fields objects
# you can access the value of the field using .val_
# you can find more hidden access option that start with ._attr_
nbnsLayer = pkt['nbns']
nbnsLayer.flags             # field of the nbns layer, named flags
nbnsLayer.flags.val_        # value of field of the nbns layer, named flags
nbnsLayer.Queries           # subfield, which contains more subfields. contain .val as well
nbnsLayer.Queries.WPAD_00_  # access to nested subfield, may contain more nesting, and/or a value

#####################
# Getting Raw bytes #
#####################
'''
 when you call apply_on_packets, you may request to receive the raw bytes of the packets
 using the shouldGetRaw parameter (default True).
 This mode is great, as you can access each layer and field raw bytes.
 This mode also allows you to save packets into new pcap File, which mean you can
 write very complex Filtering script with more flexibility compared to display filter.
  NOTE: due to tshark limitation, using display filter isn't supported while getting raw bytes. 
'''
# to get the whole packet raw bytes
pkt.GetRaw()
# to get raw bytes of layer or field
pkt.GetRaw(pkt['IP'])
pkt.GetRaw(pkt['UDP'].srcport)

################
# Full example #
################
'''
 This example will start a live capture on interface '1', 
 and print the uri of GET messages from HTTP port 80
'''
import pyWire
bpf_filter = 'tcp port 80'
display_filter = 'http.request.method == "GET"'
cap = pyWire.LiveCapture( '1' , bpf_filter , display_filter)
def PrintGets(pkt , args):
    httpLayer = pkt['http']
    print httpLayer.request_full_uri.val_
cap.apply_on_packets(PrintGets , shouldGetRaw = False)  



    