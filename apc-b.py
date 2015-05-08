#!/usr/bin/python

__description__ = 'Tool to send beacon frames'
__author__ = 'Didier Stevens'
__version__ = '0.2.0'
__date__ = '2012/06/12'

"""
requires AirPCap drivers & API dll

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/06/18: start
  2008/06/19: continue
  2008/06/20: continue
  2009/05/26: self.timestamp += 102400, cChannel
  2009/05/29: channel hopping
  2009/06/01: channel hopping
  2012/06/12: version 0.2.0 nomap

Todo:
"""

import time
import ctypes
import struct
import optparse
import random
import sched
import zlib
import binascii

AIRPCAP_LT_802_11 = 1
AIRPCAP_LT_802_11_PLUS_PPI = 4
AIRPCAP_ERRBUF_SIZE = 512
AIRPCAP_READ_BUFFER_SIZE = 10240
AIRPCAP_ADAPTER = '\\\\.\\airpcap00'
NOMAP_SUFFIX = '_nomap'

def chomp(line):
    if len(line) > 0 and line[-1] == '\n':
        return line[:-1]
    else:
        return line

def file2strings(filename):
    strings = []
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        for line in f:
            strings += [chomp(line)]
    finally:
        f.close()
    return strings

class cBeaconFrame:
    """Class for a beacon frame
    """

    def __init__(self, ESSID, channel, BSSID=None):
        self.ESSID = ESSID
        self.channel = channel
        if BSSID == None:
            self.source_address = [0x00, 0x01, 0x02, 0x03, 0x04, random.randint(0, 255)]
            self.bssid = [0x00, 0x01, 0x02, 0x03, 0x04, random.randint(0, 255)]
        else:
            self.source_address = [ord(b) for b in binascii.unhexlify(BSSID)]
            self.bssid = self.source_address
        self.sequence_number = 0
        self.timestamp = 0

    def make(self):
        frame_control = [0x80, 0x00]
        duration = [0x00, 0x00]
        destination_address = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        source_address = self.source_address
        bssid = self.bssid

        sequence = self.sequence_number * 16
        segment_fragment_number = [sequence % 256, sequence / 256]
        self.sequence_number = (self.sequence_number + 1) % 4096

        timestamp = [ord(c) for c in struct.pack('<Q', self.timestamp)]
        self.timestamp += 102400

        beacon_interval = [0x64, 0x00]
        capability_information = [0x01, 0x00]
        param_essid = self.make_tag_string(0, self.ESSID)
        param_supported_rates = self.make_tag(1, 8, [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
        param_channel = self.make_tag(3, 1, [self.channel])
        param_TIM = self.make_tag(5, 4, [0x00, 0x01, 0x00, 0x00])
        self.frame = frame_control + duration + destination_address + source_address + bssid + segment_fragment_number + timestamp + beacon_interval + capability_information + param_essid + param_supported_rates + param_channel + param_TIM

    def make_tag(self, id, len, data):
        return [id, len] + data

    def make_tag_string(self, id, data):
        return [id, len(data)] + map(ord, data)

    def get(self):
        self.make()
        c_beaconFrame = ctypes.create_string_buffer(len(self.frame))
        for i, c in enumerate(self.frame):
            c_beaconFrame[i] = chr(c)
        return c_beaconFrame

def SendBeacons(sch, delay, hAPC, beacons, oChannel):
    sch.enter(delay, 1, SendBeacons, [sch, delay, hAPC, beacons, oChannel])

    oChannel.SetAirpcapChannel()

    for oBeaconFrame in beacons:
        c_beaconFrame = oBeaconFrame.get()
        if ctypes.cdll.airpcap.AirpcapWrite(hAPC, c_beaconFrame, len(c_beaconFrame)) == 0:
            print('Error AirpcapWrite %d' % ctypes.cdll.airpcap.AirpcapGetLastError(hAPC))
            ctypes.cdll.airpcap.AirpcapClose(hAPC)
            return

    oChannel.Next()

class cChannel:
    """Channel Hopping Class
    """

    def __init__(self, hAPC):
        self.minimum = 1
        self.maximum = 14
        self.step = 5
        self.counter = 0
        self.AirpcapChannelSet = False
        self.hAPC = hAPC

    def Next(self):
        self.counter = (self.counter + self.step) % (self.maximum - self.minimum + 1)

    def Channel(self):
        return self.counter + self.minimum

    def SetChannel(self, channel):
        self.counter = channel - self.minimum

    def SetAirpcapChannel(self):
        if self.step == 0 and self.AirpcapChannelSet:
            return
        if ctypes.cdll.airpcap.AirpcapSetDeviceChannel(self.hAPC, self.Channel()) == 0:
            print('Error AirpcapSetDeviceChannel %s' % ctypes.cdll.airpcap.AirpcapGetLastError(self.hAPC))
            ctypes.cdll.airpcap.AirpcapClose(self.hAPC)
            return
        self.AirpcapChannelSet = True

def CheckFCS(frame):
    """Return true when the FCS at the end of the frame is correct, i.e. the frame is not corrupted
    """

    crc32 = zlib.crc32(frame[:-4])
    fcs = struct.unpack('l', frame[-4:])[0]
    return fcs == crc32

def ParsePacketBeacon(channel, raw_packet):
    """Parse a Beacon packet
    """

    fmt_ppi = 'BBHL'
    PpiPacketHeader = struct.unpack(fmt_ppi, raw_packet[0:struct.calcsize(fmt_ppi)])
    if (CheckFCS(raw_packet[PpiPacketHeader[2]:])):
        frame_control = struct.unpack('H', raw_packet[PpiPacketHeader[2]:PpiPacketHeader[2]+2])[0]
        if frame_control & 0xf6 == 0x80:
            fmt_ph = 'HH6s6s6sH'
            probe_header = struct.unpack(fmt_ph, raw_packet[PpiPacketHeader[2]:PpiPacketHeader[2]+struct.calcsize(fmt_ph)])
            parameters = raw_packet[PpiPacketHeader[2]+struct.calcsize(fmt_ph)+12:]
            fmt_prm = 'BB'
            parameter = struct.unpack(fmt_prm, parameters[0:struct.calcsize(fmt_prm)])
            if parameter[0] == 0 and parameter[1] > 0 and parameter[1] < 33:
                eth = ''
                for i in range(0, 6):
                    eth = eth + '%02X' % ord(probe_header[3][i])
                return (eth, parameters[2:2+parameter[1]], channel)

def Listen(listen, interval):
    ca = ctypes.create_string_buffer(AIRPCAP_ADAPTER)
    ce = ctypes.create_string_buffer(AIRPCAP_ERRBUF_SIZE)

    hAPC = ctypes.cdll.airpcap.AirpcapOpen(ca.raw, ce)

    if hAPC == 0:
        print('Error opening adapter: %s' % repr(ce.raw))
        return None

    ctypes.cdll.airpcap.AirpcapTurnLedOff(hAPC, 0)

    if ctypes.cdll.airpcap.AirpcapSetLinkType(hAPC, AIRPCAP_LT_802_11_PLUS_PPI) == 0:
        print('Error AirpcapSetLinkType %s' % ctypes.cdll.airpcap.AirpcapGetLastError(hAPC))
        ctypes.cdll.airpcap.AirpcapClose(hAPC)
        return None

    oChannel = cChannel(hAPC)
    oChannel.SetAirpcapChannel()

    hRead = ctypes.c_long(0)

    if ctypes.cdll.airpcap.AirpcapGetReadEvent(hAPC, ctypes.pointer(hRead)) == 0:
        print('Error AirpcapGetReadEvent %s' % ctypes.cdll.airpcap.AirpcapGetLastError(hAPC))
        ctypes.cdll.airpcap.AirpcapClose(hAPC)
        return None

    c_PacketBuffer = ctypes.create_string_buffer(AIRPCAP_READ_BUFFER_SIZE)
    BytesReceived = ctypes.c_long(0)

    print('Listening for %ds:' % listen)
    dESSIDs = {}

    start = time.time()
    try:
        while time.time() - start <= listen:
            # read captures and store in captures list
            captureChannel = oChannel.Channel()
            if ctypes.cdll.airpcap.AirpcapRead(hAPC, c_PacketBuffer, AIRPCAP_READ_BUFFER_SIZE, ctypes.pointer(BytesReceived)) == 0:
                print('Error AirpcapRead %s' % ctypes.cdll.airpcap.AirpcapGetLastError(hAPC))
                ctypes.cdll.airpcap.AirpcapClose(hAPC)
                return None
            captures = []
            if BytesReceived.value > 0:
                index = 0
                while index < BytesReceived.value:
                    bpf_header = struct.unpack('LLLLH', c_PacketBuffer.raw[index:index+18])
                    captures.append([captureChannel, bpf_header, c_PacketBuffer.raw[index+bpf_header[4]:index+bpf_header[4]+bpf_header[2]]])
                    # calculate index next capture
                    index = index + bpf_header[4]
                    if bpf_header[2] % 4 == 0:
                        index = index + bpf_header[2]
                    else:
                        index = index + (bpf_header[2] / 4 + 1) * 4

            # parse captures
            for capture in captures:
                beacondata = ParsePacketBeacon(capture[0], capture[2])
                if beacondata:
                    if not beacondata[0] in dESSIDs:
                        print(' \'%s\': %s channel %d' % (beacondata[1], beacondata[0], beacondata[2]))
                        dESSIDs[beacondata[0]] = beacondata

            # hop channel
            oChannel.Next()
            oChannel.SetAirpcapChannel()
            time.sleep(interval)

    except KeyboardInterrupt:
        print('Interrupted by user')

    result = []
    for BSSID, values in dESSIDs.items():
        if not values[1].endswith(NOMAP_SUFFIX) and len(values[1] + NOMAP_SUFFIX) <= 32:
            result.append((values[1] + NOMAP_SUFFIX, values[0], values[2]))

    ctypes.cdll.airpcap.AirpcapClose(hAPC)

    return result

def Main():
    """Tool to send beacon frames
    """

    oParser = optparse.OptionParser(usage='usage: %prog [options]', version='%prog ' + __version__)
    oParser.add_option('-f', '--file', help='file with beacon ESSIDs')
    oParser.add_option('-e', '--essid', default='default', help='beacon ESSID')
    oParser.add_option('-c', '--channel', type=int, default=1, help='beacon channel')
    oParser.add_option('-H', '--hop', action='store_true', default=False, help='do channel hopping')
    oParser.add_option('-i', '--interval', default=0.5, type=float, help='interval in seconds between channel hops')
    oParser.add_option('-l', '--listen', default=60, type=int, help='listening period (60s default)')
    oParser.add_option('-n', '--nomap', action='store_true', default=False, help='send _nomap beacons')
    (options, args) = oParser.parse_args()

    if len(args) != 0:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')

    else:
        if options.nomap:
            listenResult = Listen(options.listen, options.interval)
            if listenResult == None or listenResult == []:
                return

        ca = ctypes.create_string_buffer(AIRPCAP_ADAPTER)
        ce = ctypes.create_string_buffer(AIRPCAP_ERRBUF_SIZE)

        hAPC = ctypes.cdll.airpcap.AirpcapOpen(ca.raw, ce)

        if hAPC == 0:
            print('Error opening adapter: %s' % repr(ce.raw))
            return

        ctypes.cdll.airpcap.AirpcapTurnLedOff(hAPC, 0)

        if ctypes.cdll.airpcap.AirpcapSetLinkType(hAPC, AIRPCAP_LT_802_11) == 0:
            print('Error AirpcapSetLinkType %s' % ctypes.cdll.airpcap.AirpcapGetLastError(hAPC))
            ctypes.cdll.airpcap.AirpcapClose(hAPC)
            return

        try:
            if options.nomap:
                beacons = [cBeaconFrame(beacon[0], beacon[2], beacon[1]) for beacon in listenResult]
            elif options.file == None:
                beacons = [cBeaconFrame(options.essid, options.channel)]
            else:
                ESSIDs = file2strings(options.file)
                if ESSIDs == None:
                    print('Error reading file', options.file)
                    ctypes.cdll.airpcap.AirpcapClose(hAPC)
                    return
                beacons = [cBeaconFrame(ESSID, options.channel) for ESSID in ESSIDs]

            if not options.nomap:
                print('Channel: %d' % options.channel)
            print('Beacons:')
            for oBeaconFrame in beacons:
                print(' \'%s\'' % oBeaconFrame.ESSID)

            oChannel = cChannel(hAPC)
            oChannel.SetChannel(options.channel)
            oChannel.maximum = 13
            if not options.hop:
                oChannel.step = 0
            oSched = sched.scheduler(time.time, time.sleep)
            oSched.enter(0.1024, 1, SendBeacons, [oSched, 0.1024, hAPC, beacons, oChannel])
            oSched.run()

        except KeyboardInterrupt:
            print('Interrupted by user')

        ctypes.cdll.airpcap.AirpcapClose(hAPC)

if __name__ == '__main__':
    Main()
