===============================
pcap-cffi
===============================

*ONLY PARTIALLY FUNCTIONAL*

Usage
-----

    >>> import pcapcffi
    >>> p = pcapcffi.Pcap()
    >>> p.open_dev()  # By default the linux 'any' device is used
    >>> print repr(p.packets.next())  # p.packets is a generator that returns captured packets
    {'caplen': 110,
     'data': '\x00\x04\x00.....',
     'decoded': <impacket.ImpactPacket.LinuxSLL at 0x3af35242f350>,
     'len': 110,
     'tv_sec': 1826101773,
     'tv_usec': 137674}
    >>> print p.packet_count  # Numer of packets already capture but not returned via `p.packets`
    3191
    >>> p.close()


Features
--------

* Low level wrapper of all pcap methods.
* High level Pcap objects providing pythonic access to pcap functionality.
* Packet decoding using `impacket` if installed. *(recommended)*
* Free software: BSD license
