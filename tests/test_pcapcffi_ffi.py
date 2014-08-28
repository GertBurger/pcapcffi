#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

from pcapcffi.ffi import libpcap, errbuf


class TestPcapcffiFFI(object):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ffiimport(self):
        assert libpcap

    def test_devlookup(self):
        assert libpcap.pcap_lookupdev(errbuf)
