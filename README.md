# pyWire
pythonic interface for sniffing and analyzing packets with wireshark

This python library uses tshark in order to sniff and analyze network packets.
pyWire provides a simple yet powerful access to all data and fields of every packet that the Wireshark network protocol analyzer able to parse.
It is intended to be used by network researchers, Security analysts or any other packet enthusiast who would like to write a script instead of going over thousands of packets by hand.
Do you need to gather advanced statistics on a capture? extract all DNS queries and responses? map network entities and relations? spy on web access on your network? this library is designed for you. 

The pyWire library is based on the older pyShark library, fix many bugs and implementation problems, and extend the interface to be more.

The Library should be able to work on every OS that both Wireshark and python are able to run on. It was successfully tested on Windows and Linux (Ubuntu).

Installaion guide:
- Install python (2.6 or 2.7)
- Install Wireshark
- Install lxml lib (recommended using easy_install lxml). if needed, install vc for python. https://www.microsoft.com/en-us/download/details.aspx?id=44266
- Run windows installer for pyWire, or the usual setup install.

To start working, simply issue help(pyWire) and help(pyWire.packet).
Also see "pyWire usage.py" file under the pyWire folder.


One might ask himself, what is this guy blabbering about? I got scapy and its all I need. Here are some facts for you:
- Scapy parse protocols by itself, leading to many parsing errors, bugs, and limitation of the available protocols. On the other hand - pyWire rely on Wireshark, the most convenient, rich and powerful network protocol sniffer you can ask for. 
- Scapy still works only on python 2.6
- Scapy is poorly maintained, and hard to extend. Wireshark comes with rich protocol dissectors and can easily be extended (there is even plugin that allows to write dissectors with python!). Wireshark is constantly being maintained and updated. 

However, the design choices behind pyWire cause some limitations:
- pyWire does not parse protocols, and does not understand them - its simply shows you what Wireshark do (but in python!). Therefore it is not designed to Change, Modify, Rebuild, Send or Edit packets at all. If you need to send packets and not just to receive them, you will need to use another library for it.
- Due to limitations of the current implementation, it is impossible to sniff with pyWire on multiple Interfaces in the same instance. If you need such a thing, you may run several instances of your script, one for each interface. 
- pyWire is written in python, and as such it is much slower than wireshark.  It is currently capable of analyzing about 300 packets per second, and as such it is not recommended to use in large scale real-time environments. It is possible (and very recommended) to use a BPF in order to reduce the scale of the network traffic passing through the sniffer.
- pyWire support only the PCAP file format, and currently do not support PCAPNG. However, its relatively easy to convert pcapng into pcap using the wireshark interface.
- due to limitation of tshark interface, there are side effects to running infinite live capture for a long time, namely temporary files used by tshark (in %temp% folder). It is recommended to not leave live capture for very long periods of times, as eventually the hard disk will fill up.
- Packet objects are very memory heavy, so it is impossible to hold a large list of them in memory. pyWire works best with callbacks that can work on one packet at a time. If you wish to save packets for later use - save them in PCAP file on disk using the PCAP file object.

If you wish to contribute to pyWire, keep in mind the following guidelines:
- It should be easy to use and access data in protocols.
- It should be easy to install and run - I would prefer to rely on as few other libraries as possible. at some point I would like to get rid of the current dependency on lxml as well.
- Let wireshark do all the hard work, do not add code that parse protocols by itself in this library.

If you wish to contact the author with requests or suggestions, you may send mail to:
pywire.sniffer@gmail.com
