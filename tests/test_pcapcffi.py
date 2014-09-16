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
        devs = pcapcffi.wrappers.pcap_findalldevs()
        assert devs

    def test_pcap(self):
        pcap = pcapcffi.Pcap('any')
        assert pcap._pcap_t

        assert not pcap.activated
        pcap.activate()  # We need root for this
        assert pcap.activated

        pcap.close()

    def test_pcap_options(self):
        pcap = pcapcffi.Pcap('any')
        assert pcap._pcap_t

        assert not pcap.activated

        # Tests before activation
        s = pcap.snaplen
        pcap.snaplen = s

        assert s
        assert pcap.snaplen

        assert not pcap.promisc
        pcap.promisc = True
        assert pcap.promisc

        tstamps = pcap.tstamp_types
        assert tstamps
        assert pcap.set_tstamp_type(tstamps[0][0])

        # Tests after activation
        pcap.activate()
        datalink = pcap.datalink
        assert datalink

        datalinks = pcap.datalinks
        assert datalinks
        assert pcap.set_datalink(datalinks[0][0])

        pcap.close()
