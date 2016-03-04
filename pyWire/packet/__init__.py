'''
    packet
    
    Pythonic object for network packet.
    
    The packet object contains information about:
    - Packet Meta data
    - Packet layers
    - Packet Fields
    
    MetaData:
        when the packet arrived?
            pkt.sniff_time      - as datetime object
            pkt.sniff_timestamp - as timestamp (string)
        
        what is the size of the packet?
            pkt.length - number of bytes in the packet (string)
            pkt.captured_length - number of bytes captured of packet (string)
            
        what interface was the packet captured on? (NOT WORKING)
            ! NOTE - Currently tshark doesn't give the right information
            pkt.interface_captured - number of interface as string
        
    Printing
        I want to see the packet data like in wireshark.
            print pkt
        
        I want to see short description of the packet 
            print repr(pkt)
        
    Layers:
        Each packet is made out of protocols layers.
        
        what are the layers of the packet?
            pkt.layers - list of layers objects, lower first.
            
        what are the names of important layers?
            pkt.highest_layer   - name of the highest layer (string)
            pkt.transport_layer - name of the transport layer (string or None)
           
        I want the first layer named X, or the i'th layer:
            pkt[X]  - retrieve layer by its name. (lower taken)
            For example:
                pkt['eth'] - ethernet
                pkt['ip'] , pkt['udp'], pkt['tcp'], pkt['http']....
            pkt[i]  - retrieve layer by its index.
            
        Special layers:
            pkt.geninfo - special general info layer
            pkt.frame   - special frame layer
        
    Fields:
        Each layer contains fields, which can contain sub fields etc...
        What is the subfields tree of the packet\layer\field?
            pkt.PrintSubFieldsTree()
            pkt['layer'].PrintSubFieldsTree()
            pkt['layer'].fieldName.PrintSubFieldsTree()
            
        In order to access a field, refer to it by its name:
            pkt['layer'].field
            pkt['layer'].field.subField
            pkt['layer'].field.subField.subField  ...
            
        NOTE: layer (or field) can have several sub fields with the same name.
              In that case, 
                pkt['layer'].field
              will return a LIST object (of fields), not a FIELD object.
              
              However, if its unknown whether only one field or more, just do:
              for subField in pkt['layer'].field:
                # DO STUFF HERE with subField object
              
              because subfield object iterator will return itself.
            
        In order to access a field value, use .val_
            pkt['tcp'].src.val_  -> will return the src ip
            
        Some special attributes of fields:
            pkt['tcp'].src._attr_showname - string as showed by wireshark
            pkt['eth'].dst._attr_value - raw value of the field
        
        Find fields with unknown names in runtime:
            IterateSubfieldsNames
                iterate over the subfield names of this layer\field
            IterateSubfields
                iterate over the subfield objects of this layer\field
            IterateSubFieldsTree
                iterate over the subfields tree objects of this layer\field (dfs)
            SearchSubField
                get list of field objects with given substring in their name
                can also search recursively (tree dfs)
            
            for example:
                pkt['DNS'].SearchSubField('qry',True)
                will return list of fields that are related to the DNS query
        
    RawBytes:
        packet object also holds the original captured raw bytes.
        What are the raw bytes of the packet?
            pkt.GetRaw()    - as string
        
        what are the raw bytes of specific layer \ subfield?
            pkt.GetRaw(pkt['layer'])
            pkt.GetRaw(pkt['layer'].subField)
        
'''