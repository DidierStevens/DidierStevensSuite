#!/usr/bin/python
"""V0.2 2015/01/27

Program to sequence channel switching of an AirPCap adapter

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/06/09: start
  2015/01/27: V0.2 added option -c

requires AirPCap drivers & API dll
"""

import time
from ctypes import *
from optparse import OptionParser

class cChannel:
    def __init__(self, step, channels):
        self.minimum = 1
        self.maximum = 14
        self.step = step
        self.counter = 0
        if channels == '':
            self.channels = []
        else:
            self.channels = map(int, channels.split(','))
            self.remainingChannels = self.channels

    def Next(self):
        if self.channels == []:
            self.counter = (self.counter + self.step) % (self.maximum - self.minimum + 1)
        else:
            self.remainingChannels = self.remainingChannels[1:]
            if self.remainingChannels == []:
                self.remainingChannels = self.channels

    def Channel(self):
        if self.channels == []:
            self.channel = self.counter + self.minimum
            return self.channel
        else:
            return self.remainingChannels[0]

def Main():
    """Create a VBScript containing an embedded (executable) file
    """

    parser = OptionParser(usage="usage: %prog [options]", version="%prog 0.1")
    parser.add_option("-i", "--interval", default="0.5", type="float", help="interval in seconds between channel switchs")
    parser.add_option("-s", "--step", default="5", type="int", help="step between channels")
    parser.add_option("-c", "--channels", default="", help="sequence of channels")
    parser.add_option("-q", "--quiet", action="store_true", default=False, help="don't print channel switching")
    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.print_help()
        print ""
        print "  Use this program to sequence channel switching of an AirPCap adapter"
        print "  Source code put in the public domain by Didier Stevens, no Copyright"
        print "  Use at your own risk"
        print "  https://DidierStevens.com"

    else:
        ca = create_string_buffer("\\\\.\\airpcap00")
        ce = create_string_buffer(256)

        hAPC = cdll.airpcap.AirpcapOpen(ca.raw, ce.raw)

        if hAPC == 0:
            print "Error opening adapter: %s" % repr(ce.raw)
            return

        oChannel = cChannel(options.step, options.channels)
        if options.channels == '':
            oChannel.step = options.step
        else:
            oChannel.channels = map(int, options.channels.split(','))

        try:
            while 1:
                if cdll.airpcap.AirpcapSetDeviceChannel(hAPC, oChannel.Channel()) == 0:
                    print "Error AirpcapSetDeviceChannel %s" % cdll.airpcap.AirpcapGetLastError(hAPC)
                    cdll.airpcap.AirpcapClose(hAPC)
                    exit
                if not options.quiet:
                    print "Channel %d" % (oChannel.Channel())
                oChannel.Next()
                time.sleep(options.interval)
        except KeyboardInterrupt:
            print "Interrupted by user"

        cdll.airpcap.AirpcapClose(hAPC)

Main()
