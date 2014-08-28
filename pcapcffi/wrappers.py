from .ffi import pcap_error, errbuf, ffi, libpcap


def findalldevs():
    devs = []
    pcap_if_t = ffi.new('pcap_if_t **')
    ret = libpcap.pcap_findalldevs(pcap_if_t, errbuf)

    if ret:
        pcap_error()

    dev = pcap_if_t[0]
    while dev:
        devs.append(ffi.string(dev.name))
        dev = dev.next

    libpcap.pcap_freealldevs(pcap_if_t[0])

    return devs
