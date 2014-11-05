#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

import pytest

from pcapcffi.ffi import libpcap, errbuf
from pcapcffi import wrappers as w


class TestPcapcffiFFI(object):
    def test_ffiimport(self):
        assert libpcap

    def test_devlookup(self):
        assert libpcap.pcap_lookupdev(errbuf)

    def test_wrappers(self):
        pcap_t = w.pcap_create('any')
        assert w.pcap_set_snaplen(pcap_t, 1024) == 0
        assert w.pcap_snapshot(pcap_t)
        assert w.pcap_set_promisc(pcap_t, True) == 0
        assert w.pcap_set_promisc(pcap_t, False) == 0

        assert w.pcap_set_rfmon(pcap_t, True) == 0
        assert w.pcap_set_rfmon(pcap_t, False) == 0

        assert w.pcap_set_timeout(pcap_t, 100) == 0
        assert w.pcap_set_buffer_size(pcap_t, 65535) == 0

        assert w.pcap_set_tstamp_type(pcap_t, 0) == 0
        assert w.pcap_list_tstamp_types(pcap_t)

        assert w.pcap_tstamp_type_val_to_name(0)
        assert w.pcap_tstamp_type_val_to_description(0)
        assert w.pcap_tstamp_type_name_to_val(w.pcap_tstamp_type_val_to_name(0)) >= 0

        with pytest.raises(w.PcapError):
            stats = w.pcap_stats(pcap_t)
            assert stats

    def test_wrappers_activated(self):
        pcap_t = w.pcap_create('any')
        w.pcap_activate(pcap_t)

        assert w.pcap_datalink(pcap_t)
        assert w.pcap_datalink_val_to_name(0)
        assert w.pcap_datalink_val_to_description(0)
        assert w.pcap_datalink_name_to_val(w.pcap_datalink_val_to_name(0)) >= 0

        stats = w.pcap_stats(pcap_t)
        assert 'ps_drop' in stats
