"""
This module contains functions to turn TShark XML parts into Packet objects.
"""
# might be able to use xml.etree.cElementTree instead
import lxml.objectify

from pyWire.packet.packet import Packet

def packet_from_xml_packet(xml_pkt):
    #return xml_pkt
    xml_pkt_obj = lxml.objectify.fromstring(xml_pkt)
    return Packet( xml_pkt_obj )
