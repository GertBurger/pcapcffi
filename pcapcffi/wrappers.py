import logging

from .ffi import errbuf, ffi, libpcap

log = logging.getLogger(__name__)
ignore_warnings = False


class PcapError(Exception):
    def __init__(self, pcap_error, msg=None):
        self.pcap_error = pcap_error
        if not msg:
            msg = ffi.string(libpcap.pcap_statustostr(pcap_error))
        super(PcapError, self).__init__(msg)


class PcapWarning(PcapError):
    pass


def raise_errbuf(pcap_error):
    raise PcapError(pcap_error, ffi.errbuf)


def raise_geterr(pcap_t):
    raise PcapError(libpcap.pcap_geterr(pcap_t))


def pcap_findalldevs():
    devs = []
    pcap_if_t = ffi.new('pcap_if_t **')
    ret = libpcap.pcap_findalldevs(pcap_if_t, errbuf)

    if ret:
        raise_errbuf()

    dev = pcap_if_t[0]
    while dev:
        devs.append(ffi.string(dev.name))
        dev = dev.next

    libpcap.pcap_freealldevs(pcap_if_t[0])

    return devs


def pcap_snapshot(pcap_t):
    return libpcap.pcap_snapshot(pcap_t)


def pcap_create(dev):
    pcap_t = libpcap.pcap_create(dev, errbuf)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_open_offline(fname):
    pcap_t = libpcap.pcap_open_offline(fname, errbuf)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_open_offline_with_tstamp_precision(fname, precision):
    pcap_t = libpcap.pcap_open_offline_with_tstamp_precision(fname, precision, errbuf)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_fopen_offline(fp):
    pcap_t = libpcap.pcap_fopen_offline(fp, errbuf)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_fopen_offline_with_tstamp_precision(fp, precision):
    pcap_t = libpcap.pcap_fopen_offline_with_tstamp_precision(fp, precision, errbuf)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_open_dead(linktype, snaplen):
    pcap_t = libpcap.pcap_open_dead(linktype, snaplen)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision):
    pcap_t = libpcap.pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision)

    if not pcap_t:
        raise_errbuf()

    return pcap_t


def pcap_activate(pcap_t):
    ret = libpcap.pcap_activate(pcap_t)

    if ret < 0:
        raise PcapError(ret)
    elif ret > 0:
        if not ignore_warnings:
            raise PcapWarning(ret)
            return False
        else:
            log.warning("Activation warning %s", libpcap.pcap_statustostr(ret))

    return True


def pcap_close(pcap_t):
    libpcap.pcap_close(pcap_t)


def pcap_set_snaplen(pcap_t, snaplen):
    return libpcap.pcap_set_snaplen(pcap_t, snaplen)


def pcap_set_promisc(pcap_t, promisc):
    return libpcap.pcap_set_promisc(pcap_t, int(promisc))


def pcap_can_set_rfmon(pcap_t):
    return libpcap.pcap_can_set_rfmon(pcap_t)


def pcap_set_rfmon(pcap_t, rfmon):
    return libpcap.pcap_set_rfmon(pcap_t, int(rfmon))


def pcap_set_timeout(pcap_t, ms):
    ret = libpcap.pcap_set_timeout(pcap_t, ms)
    if ret == -1:
        raise PcapError(libpcap.PCAP_ERROR_ACTIVATED)
    return ret


def pcap_set_buffer_size(pcap_t, size):
    return libpcap.pcap_set_buffer_size(pcap_t, size)


def pcap_set_tstamp_type(pcap_t, tstamp_type):
    return libpcap.pcap_set_tstamp_type(pcap_t, tstamp_type)


def pcap_list_tstamp_types(pcap_t):
    tstamp_types = []
    types_list = ffi.new('int**')

    count = libpcap.pcap_list_tstamp_types(pcap_t, types_list)

    if count:
        for i in range(count):
            tstamp_types.append(types_list[0][i])

    libpcap.pcap_free_tstamp_types(types_list[0])

    return tstamp_types


def pcap_tstamp_type_val_to_name(tstamp_type):
    return ffi.string(libpcap.pcap_tstamp_type_val_to_name(tstamp_type))


def pcap_tstamp_type_val_to_description(tstamp_type):
    return ffi.string(libpcap.pcap_tstamp_type_val_to_description(tstamp_type))


def pcap_tstamp_type_name_to_val(tstamp):
    ret = libpcap.pcap_tstamp_type_name_to_val(tstamp)
    if ret == libpcap.PCAP_ERROR:
        raise RuntimeError('Cannot determine tstamp type name for %s' % tstamp)

    return ret


def pcap_datalink(pcap_t):
    datalink = libpcap.pcap_datalink(pcap_t)
    if datalink == libpcap.PCAP_ERROR_NOT_ACTIVATED:
        raise PcapError(PCAP_ERROR_NOT_ACTIVATED)

    return datalink


def pcap_set_datalink(pcap_t, dlt):
    return libpcap.pcap_set_datalink(pcap_t, dlt)


def pcap_list_datalinks(pcap_t):
    datalinks_types = []
    types_list = ffi.new('int**')

    count = libpcap.pcap_list_datalinks(pcap_t, types_list)

    if count:
        for i in range(count):
            datalinks_types.append(types_list[0][i])

    libpcap.pcap_free_datalinks(types_list[0])

    return datalinks_types


def pcap_datalink_val_to_name(dlt):
    return ffi.string(libpcap.pcap_datalink_val_to_name(dlt))


def pcap_datalink_val_to_description(dlt):
    return ffi.string(libpcap.pcap_datalink_val_to_description(dlt))


def pcap_datalink_name_to_val(datalink):
    ret = libpcap.pcap_datalink_name_to_val(datalink)
    if ret == libpcap.PCAP_ERROR:
        raise RuntimeError('Cannot determine datalink name for %s' % datalink)

    return ret


def pcap_stats(pcap_t):
    pcap_stat = ffi.new('struct pcap_stat *')
    ret = libpcap.pcap_stats(pcap_t, pcap_stat)

    if ret < 0:
        raise PcapError(ret)

    return dict(ps_recv=pcap_stat.ps_recv, ps_drop=pcap_stat.ps_drop, ps_ifdrop=pcap_stat.ps_ifdrop)


def pcap_dispatch(pcap_t, cnt, callback, user):
    ret = libpcap.pcap_dispatch(pcap_t, cnt, callback, ffi.new('u_char[]', user))

    if ret == -1:
        raise_geterr(pcap_t)
    elif ret == -2:
        return None
    else:
        return ret


PCAP_ERRBUF_SIZE = libpcap.PCAP_ERRBUF_SIZE
PCAP_ERROR = libpcap.PCAP_ERROR
PCAP_ERROR_BREAK = libpcap.PCAP_ERROR_BREAK
PCAP_ERROR_NOT_ACTIVATED = libpcap.PCAP_ERROR_NOT_ACTIVATED
PCAP_ERROR_ACTIVATED = libpcap.PCAP_ERROR_ACTIVATED
PCAP_ERROR_NO_SUCH_DEVICE = libpcap.PCAP_ERROR_NO_SUCH_DEVICE
PCAP_ERROR_RFMON_NOTSUP = libpcap.PCAP_ERROR_RFMON_NOTSUP
PCAP_ERROR_NOT_RFMON = libpcap.PCAP_ERROR_NOT_RFMON
PCAP_ERROR_PERM_DENIED = libpcap.PCAP_ERROR_PERM_DENIED
PCAP_ERROR_IFACE_NOT_UP = libpcap.PCAP_ERROR_IFACE_NOT_UP
PCAP_ERROR_CANTSET_TSTAMP_TYPE = libpcap.PCAP_ERROR_CANTSET_TSTAMP_TYPE
PCAP_ERROR_PROMISC_PERM_DENIED = libpcap.PCAP_ERROR_PROMISC_PERM_DENIED
PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = libpcap.PCAP_ERROR_TSTAMP_PRECISION_NOTSUP
PCAP_WARNING = libpcap.PCAP_WARNING
PCAP_WARNING_PROMISC_NOTSUP = libpcap.PCAP_WARNING_PROMISC_NOTSUP
PCAP_WARNING_TSTAMP_TYPE_NOTSUP = libpcap.PCAP_WARNING_TSTAMP_TYPE_NOTSUP
