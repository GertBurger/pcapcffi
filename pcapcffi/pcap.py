from Queue import Queue
import thread
import threading

from . import wrappers as w
from .wrappers import PcapError, PcapWarning

__all__ = [PcapError, PcapWarning, 'Pcap']
_pcap_user_mapping = dict()


@w.ffi.callback('void(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)')
def _packet_handler(user, hdr, buff):
    user = w.ffi.string(user)
    buff = w.ffi.buffer(buff, hdr.len)[:]

    obj = _pcap_user_mapping[user]
    obj._packet_handler(hdr, buff)


class Pcap(object):
    def __init__(self, promisc=True, buffer_size=None, read_timeout=100, show_packets=False):
        self._pcap_t = None
        self._packets = None

        assert promisc in (True, False), "promisc must be either True or False"
        self._promisc = promisc

        self._buffer_size = buffer_size
        self._read_timeout = read_timeout

        assert show_packets in (True, False), "show_packets must be either True or False"
        self._show_packets = show_packets

        self._pcap_lock = threading.Lock()

        try:
            from impacket.ImpactDecoder import LinuxSLLDecoder
            self._decoder = LinuxSLLDecoder()
        except ImportError:
            self._decoder = None

    def _set_buffer(self, buffer_size):
        w.pcap_set_buffer_size(self._pcap_t, buffer_size)

    def _set_timeout(self, read_timeout):
        w.pcap_set_timeout(self._pcap_t, read_timeout)

    @property
    def packets(self):
        for p in iter(self._packets.get, None):
            yield p

    @property
    def packet_count(self):
        return self._packets.qsize()

    @property
    def activated(self):
        return self._pcap_t is not None

    @property
    def snaplen(self):
        if not self.activated:
            raise PcapError(w.PCAP_ERROR_NOT_ACTIVATED)
        return w.pcap_snapshot(self._pcap_t)

    @snaplen.setter
    def snaplen(self, snaplen):
        if not self.activated:
            raise PcapError(w.PCAP_ERROR_NOT_ACTIVATED)
        return w.pcap_set_snaplen(self._pcap_t, snaplen) == 0

    @property
    def promisc(self):
        return self._promisc

    def _set_promisc(self, state):
        w.pcap_set_promisc(self._pcap_t, state)

    @property
    def tstamp_types(self):
        return [(val, w.pcap_tstamp_type_val_to_name(val), w.pcap_tstamp_type_val_to_description(val)) for val in w.pcap_list_tstamp_types(self._pcap_t)]

    @property
    def datalink(self):
        dl = w.pcap_datalink(self._pcap_t)

        for dl_type, dl_name, dl_description in self.datalinks:
            if dl == dl_type:
                return dl_name

        return None

    def set_datalink(self, dlt):
        return w.pcap_set_datalink(self._pcap_t, dlt) == 0

    @property
    def datalinks(self):
        if not self.activated:
            raise PcapError(w.PCAP_ERROR_NOT_ACTIVATED)
        return [(val, w.pcap_datalink_val_to_name(val), w.pcap_datalink_val_to_description(val)) for val in w.pcap_list_datalinks(self._pcap_t)]

    def set_tstamp_type(self, tstamp_type):
        return w.pcap_set_tstamp_type(self._pcap_t, tstamp_type) == 0

    def _activate(self):
        self._packets = Queue()
        w.pcap_activate(self._pcap_t)

    def _start(self):
        self._activate()
        self._start_loop()

    def _start_loop(self):
        thread.start_new_thread(self._loop, tuple())

    def _loop(self):
        user = str(id(self))
        _pcap_user_mapping[user] = self

        while True:
            with self._pcap_lock:
                if self.activated:
                    ret = w.pcap_dispatch(self._pcap_t, -1, _packet_handler, user)
                    if ret is None:
                        break
                else:
                    break

        del _pcap_user_mapping[user]

    def close(self):
        if self._pcap_t:
            w.pcap_breakloop(self._pcap_t)

        with self._pcap_lock:
            if self._pcap_t:
                w.pcap_close(self._pcap_t)
                self._pcap_t = None

    def _packet_handler(self, hdr, packet):
        packet_dict = dict(
            tv_sec=hdr.ts.tv_sec,
            tv_usec=hdr.ts.tv_usec,
            len=hdr.len,
            caplen=hdr.caplen,
            data=packet,
            decoded=None
        )

        if self._decoder:
            packet_dict['decoded'] = self._decoder.decode(packet)

            if self._show_packets:
                print packet_dict['decoded']

        self._packets.put(packet_dict)

    def open_dev(self, dev='any'):
        """Create and activate pcap on a device. If no `dev` is specified then
        'any' i used.
        """
        self._pcap_t = w.pcap_create(dev)
        self._set_promisc(self._promisc)

        if self._buffer_size:
            self._set_buffer(self._buffer_size)

        if self._read_timeout:
            self._set_timeout(self._read_timeout)

        self._start()

    def open_file(self, filename):
        """Create and activate pcap with a file or filename."""

        if isinstance(filename, basestring):
            self._pcap_t = w.pcap_open_offline(filename)
        else:
            self._pcap_t = w.pcap_fopen_offline(filename)
        self._start()
