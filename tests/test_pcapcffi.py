#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

import pytest

import pcapcffi


class TestPcapcffi(object):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_findalldevs(self):
        devs = pcapcffi.findalldevs()
        assert devs

    def test_pcap(self):
        pcap = pcapcffi.Pcap('any')
        assert pcap._pcap_t

        assert not pcap.activated
        #pcap.activate() # We need root for this
        #assert pcap.activated

        pcap.close()

    def test_pcap_options(self):
        pcap = pcapcffi.Pcap('any')
        assert pcap._pcap_t

        assert not pcap.activated

        assert pcap.set_snaplen(1024)
        assert pcap.snapshot
        assert pcap.set_promisc(False)
        assert pcap.set_promisc(True)

        assert pcap.can_set_rfmon()
        assert pcap.set_rfmon(False)
        assert pcap.set_rfmon(True)

        assert pcap.set_timeout(100)
        assert pcap.set_buffer_size(65535)

        assert pcap.set_tstamp_type(0)
        assert pcap.list_tstamp_types()

        assert pcap.tstamp_type_val_to_name(0)
        assert pcap.tstamp_type_val_to_description(0)
        assert pcap.tstamp_type_name_to_val(pcap.tstamp_type_val_to_name(0)) >= 0

        assert pcap.datalink()
        assert pcap.datalink_val_to_name(0)
        assert pcap.datalink_val_to_description(0)
        assert pcap.datalink_name_to_val(pcap.datalink_val_to_name(0)) >= 0

        pcap.close()
