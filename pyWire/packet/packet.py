import datetime
import os

from pyWire.packet import consts
from pyWire.packet.layer import Layer

class Packet(object):
    """
    A packet object which contains layers.
    Layers can be accessed via index or name.
    """
 
    def __init__(self, xml_pkt_obj, fields_type=None):
        """
        Creates a Packet object with the given layers and info.

        :param xml_pkt_obj: An xml object which contains the packet data.
        """
        # create layer for each protocol
        layers = [Layer(proto, fields_type=fields_type) for proto in xml_pkt_obj.proto]
        geninfo, frame, layers = layers[0], layers[1], layers[2:]
        # frame.raw_mode = True
        
        if layers is None:
            self.layers = []
        else:
            self.layers = layers
        self.geninfo = geninfo
        self.frame = frame
        self.interface_captured = frame.TryGetAttribute('interface_id')
        if self.interface_captured is not None:
            self.interface_captured = self.interface_captured.val_
        self.captured_length = geninfo.caplen.val_
        self.length = geninfo.len.val_
        self.sniff_timestamp = geninfo.timestamp._attr_value
        self.hasRaw = False
        
    def __getitem__(self, item):
        """
        Gets a layer according to its index or its name

        :param item: layer index or name
        :return: Layer object.
        """
        if isinstance(item, int):
            return self.layers[item]
        for layer in self.layers:
            if layer.layer_name == item.lower():
                return layer
        raise KeyError('Layer does not exist in packet')

    def __contains__(self, item):
        """
        Checks if the layer is inside the packet.

        :param item: name of the layer
        """
        try:
            self[item]
            return True
        except KeyError:
            return False

    def GetRaw(self, subObject = None):
        '''
        Works only if raw bytes are available, return None if not.
        return the raw bytes for the given sub object in this packet.
        sub object may be layer or field.
        if None, return all bytes in this packets.
        '''
        if self.hasRaw:
            if subObject is None:
                return self.raw
            else:
                startPos = int(subObject._attr_pos)
                endPos = startPos + int(subObject._attr_size)
                return self.raw[startPos:endPos]
        else:
            return None
         
    @property
    def sniff_time(self):
        '''
        The time when the packet was received on the interface (as datetime)
        '''
        try:
            timestamp = float(self.sniff_timestamp)
        except ValueError:
            # If the value after the decimal point is negative, discard it
            # Google: wireshark fractional second
            timestamp = float(self.sniff_timestamp.split(".")[0])
        return datetime.datetime.fromtimestamp(timestamp)

    def __repr__(self):
        '''
        print short representation of the packet
        '''
        transport_protocol = ''
        if self.transport_layer != self.highest_layer and self.transport_layer is not None:
            transport_protocol = self.transport_layer + '/'
        return '<%s%s Packet>' % (transport_protocol, self.highest_layer)

    def __str__(self):
        '''
            return string representation of the packet.
        '''
        s = self._packet_string
        for layer in self.layers:
            s += str(layer)
        return s

    def PrintSubFieldsTree(self,dontShowHidden = True):
        '''
        print the sub fields tree of the layer
        '''
        for layer in self.layers:
            print 'Layer: ' + layer._name
            print TabString(layer.StrSubFieldsTree(dontShowHidden))
        
    @property
    def _packet_string(self):
        """
        A simple pretty string that represents the packet.
        """
        return 'Packet (Length: %s)%s' %(self.length, os.linesep)

    @property
    def highest_layer(self):
        '''
            return the highest layer in the packet.
        '''
        return self.layers[-1].layer_name.upper()

    @property
    def transport_layer(self):
        '''
            return the transport layer in the packet.
        '''
        for layer in consts.TRANSPORT_LAYERS:
            if layer in self:
                return layer
                
def TabString(theStr):
    theStr = '\t' + theStr.replace('\n' , '\n\t')
    return theStr[:-1]
  