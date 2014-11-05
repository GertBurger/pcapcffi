from . import wrappers as w
from .wrappers import PcapError, PcapWarning


class Pcap(object):
    def __init__(self, dev='any'):
        self._dev = dev
        self._pcap_t = self._create(dev)
        self._activated = False
        self._promisc = False

    @property
    def activated(self):
        return self._activated

    @property
    def opened(self):
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

    @promisc.setter
    def promisc(self, state):
        self._promisc = state
        if self.activated:
            raise PcapError(w.PCAP_ERROR_ACTIVATED)
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

    def _create(self, dev):
        return w.pcap_create(dev)

    def activate(self):
        self._activated = w.pcap_activate(self._pcap_t)

    def close(self):
        if self._pcap_t:
            w.pcap_close(self._pcap_t)
            self._pcap_t = None
            self._activated = False
            self._promisc = False
