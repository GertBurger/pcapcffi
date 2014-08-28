from .ffi import pcap_error, pcap_statustostr, errbuf, ffi, libpcap


class Pcap(object):
    def __init__(self, dev):
        self._dev = dev
        self._pcap_t = self._create(dev)
        self._activated = False

    @property
    def activated(self):
        return self._activated

    @property
    def snapshot(self):
        return libpcap.pcap_snapshot(self._pcap_t)

    def _create(self, dev):
        pcap_t = libpcap.pcap_create(dev, errbuf)

        if not pcap_t:
            pcap_error()

        return pcap_t

    def activate(self, ignore_warnings=False):
        ret = libpcap.pcap_activate(self._pcap_t)

        if ret < 0:
            raise RuntimeError("Failed to activate pcap %s: %s" % (ret, pcap_statustostr(ret)))
        elif ret > 0:
            if not ignore_warnings:
                raise RuntimeError("Warning: %s" % pcap_statustostr(ret))
                return False

        self._activated = True
        return True

    def close(self):
        libpcap.pcap_close(self._pcap_t)

    def set_snaplen(self, snaplen):
        return libpcap.pcap_set_snaplen(self._pcap_t, snaplen) == 0

    def set_promisc(self, promisc):
        return libpcap.pcap_set_promisc(self._pcap_t, int(promisc)) == 0

    def can_set_rfmon(self):
        return libpcap.pcap_can_set_rfmon(self._pcap_t) == 0

    def set_rfmon(self, rfmon):
        return libpcap.pcap_set_rfmon(self._pcap_t, int(rfmon)) == 0

    def set_timeout(self, ms):
        return libpcap.pcap_set_timeout(self._pcap_t, ms) == 0

    def set_buffer_size(self, size):
        return libpcap.pcap_set_buffer_size(self._pcap_t, size) == 0

    def set_tstamp_type(self, tstamp_type):
        return libpcap.pcap_set_tstamp_type(self._pcap_t, tstamp_type) == 0

    def list_tstamp_types(self):
        tstamp_types = []
        types_list = ffi.new('int**')

        count = libpcap.pcap_list_tstamp_types(self._pcap_t, types_list)

        if count:
            for i in range(count):
                tstamp_types.append(types_list[0][i])

        libpcap.pcap_free_tstamp_types(types_list[0])

        return tstamp_types

    def tstamp_type_val_to_name(self, tstamp_type):
        return ffi.string(libpcap.pcap_tstamp_type_val_to_name(tstamp_type))

    def tstamp_type_val_to_description(self, tstamp_type):
        return ffi.string(libpcap.pcap_tstamp_type_val_to_description(tstamp_type))

    def tstamp_type_name_to_val(self, tstamp):
        ret = libpcap.pcap_tstamp_type_name_to_val(tstamp)
        if ret == libpcap.PCAP_ERROR:
            raise RuntimeError('Cannot determine tstamp type name for %s' % tstamp)

        return ret

    def datalink(self):
        return libpcap.pcap_datalink(self._pcap_t)

    def set_datalink(self, dlt):
        return libpcap.pcap_set_datalink(self._pcap_t, dlt) == 0

    def list_datalinks(self):
        datalinks_types = []
        types_list = ffi.new('int**')

        count = libpcap.pcap_list_datalinks(self._pcap_t, types_list)

        if count:
            for i in range(count):
                datalinks_types.append(types_list[0][i])

        libpcap.pcap_free_datalinks(types_list[0])

        return datalinks_types

    def datalink_val_to_name(self, dlt):
        return ffi.string(libpcap.pcap_datalink_val_to_name(dlt))

    def datalink_val_to_description(self, dlt):
        return ffi.string(libpcap.pcap_datalink_val_to_description(dlt))

    def datalink_name_to_val(self, datalink):
        ret = libpcap.pcap_datalink_name_to_val(datalink)
        if ret == libpcap.PCAP_ERROR:
            raise RuntimeError('Cannot determine datalink name for %s' % datalink)

        return ret
