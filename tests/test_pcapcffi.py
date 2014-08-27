#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pcapcffi
----------------------------------

Tests for `pcapcffi` module.
"""

from pcapcffi import pcapcffi


class TestPcapcffi(object):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_ffiimport(self):
        from pcapcffi.ffi import ffi
        assert ffi.verify('#include<pcap/pcap.h>')
