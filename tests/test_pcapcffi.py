#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

import pytest

import pcapcffi
from pcapcffi.wrappers import PcapError


def test_findalldevs():
    devs = pcapcffi.wrappers.pcap_findalldevs()
    assert devs


def test_pcap():
    pcap = pcapcffi.Pcap()
    assert pcap._pcap_t is None
    assert not pcap.activated

    with pytest.raises(PcapError):
        pcap.snaplen()

    with pytest.raises(PcapError):
        pcap.datalinks()

    pcap.close()
