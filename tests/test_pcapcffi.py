#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

import pytest

import pcapcffi


def test_findalldevs():
    devs = pcapcffi.wrappers.pcap_findalldevs()
    assert devs


def test_pcap():
    pcap = pcapcffi.Pcap('any')
    assert pcap._pcap_t

    assert not pcap.activated
    pcap._activate()  # We need root for this
    assert pcap.activated

    with pytest.raises(pcapcffi.PcapError):
        pcap._activate()  # We need root for this

    with pytest.raises(pcapcffi.PcapError):
        pcap.promisc = False

    pcap.close()


def test_pcap_options():
    pcap = pcapcffi.Pcap('any')
    assert pcap._pcap_t

    assert not pcap.activated
    s = 0

    # Tests before activation
    with pytest.raises(pcapcffi.PcapError):
        s = pcap.snaplen

    with pytest.raises(pcapcffi.PcapError):
        pcap.snaplen = 1

    assert s == 0

    assert pcap.promisc
    pcap.promisc = False
    assert not pcap.promisc

    tstamps = pcap.tstamp_types
    assert tstamps
    assert pcap.set_tstamp_type(tstamps[0][0])

    with pytest.raises(pcapcffi.PcapError):
        pcap.datalinks

    # Tests after activation
    pcap._activate()
    datalink = pcap.datalink
    assert datalink

    datalinks = pcap.datalinks
    assert datalinks
    assert pcap.set_datalink(datalinks[0][0])

    tstamps = pcap.tstamp_types
    assert tstamps

    pcap.close()
