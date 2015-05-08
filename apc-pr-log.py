#!/usr/bin/python
"""V0.1 2008/04/04

Tool to log WiFi probe requests

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
 2008/04/04: start
 2008/04/06: airpcap queue processing
 2008/04/07: beacon frames, FCS checking
 2008/04/08: FCS checking
 2008/06/10: channel hopping with cChannel, refactoring, oui.txt
 2008/06/11: pickle
 2008/06/12: OUI class
 2008/06/16: nolog option, exclude option
 2008/06/17: interval option, cPRData: packet count per day
 2008/06/23: cleanup
 
requires AirPCap drivers & API dll
"""

import time
from ctypes import *
from struct import *
import zlib
from optparse import OptionParser
import re
import pickle
import os.path

AIRPCAP_LT_802_11_PLUS_PPI = 4
AIRPCAP_ERRBUF_SIZE = 512
AIRPCAP_READ_BUFFER_SIZE = 10240
AIRPCAP_ADAPTER = '\\\\.\\airpcap00'

PICKLE_FILE = 'apc-pr-log.pkl'
LOG_FILE = 'apc-pr-log.txt'
REPORT_FILE = 'apc-pr-log-report.txt'
OUI_FILE = 'oui.txt'

def chomp(line):
    if len(line) > 0 and line[-1] == '\n':
        return line[:-1]
    else:
        return line

class cChannel:
    """Channel Hopping Class
    """
    
    def __init__(self):
        self.minimum = 1
        self.maximum = 14
        self.step = 1
        self.counter = 0
    
    def next(self):
        self.counter = (self.counter + self.step) % (self.maximum - self.minimum + 1)

    def channel(self):
        return self.counter + self.minimum

class cPRData:
    """Class with probe request data for a given MAC address
    """
    
    def __init__(self, MAC):
        self.MAC = MAC
        self.firstseen = None
        self.lastseen = None
        self.SSIDs = []
        self.packets = {}

    def __init__(self, MAC, timestamp, SSID):
        self.MAC = MAC
        self.firstseen = timestamp
        self.lastseen = timestamp
        self.SSIDs = [SSID]
        self.packets = {timestamp[:8]:1}

    def add(self, timestamp, SSID):
        if self.firstseen == None:
            self.firstseen = timestamp
            self.lastseen = timestamp
        else:
            self.lastseen = timestamp
        if not SSID in self.SSIDs:
            self.SSIDs.append(SSID)
        if timestamp[:8] in self.packets:
            self.packets[timestamp[:8]] += 1
        else:
            self.packets[timestamp[:8]] = 1

class cExclude:
    """Class to exclude MAC addresses or OUIs
    """
    
    def __init__(self, filename):
        self.excludeMACs = []
        self.excludeOUIs = []
        if filename != None:
            f = open(filename, 'r')
            for line in f:
                line = chomp(line.upper())
                if len(line) == 6:
                    self.excludeOUIs.append(line)
                elif len(line) == 12:
                    self.excludeMACs.append(line)
            f.close()

    def test(self, MAC):
        MAC = MAC.upper()
        return MAC[0:6] in self.excludeOUIs or MAC in self.excludeMACs

class cPacket(object):
    """Class to parse packets
    """
    
    def __init__(self, bpf_header, raw_packet):
        self.bpf_header = bpf_header
        self.raw_packet = raw_packet
        self.frame_control = None
        fmt_ppi = 'BBHL' # pph_version pph_flags pph_len pph_dlt
        self.PpiPacketHeader = unpack(fmt_ppi, self.raw_packet[0:calcsize(fmt_ppi)])
        if self.__CheckFCS():
            self.frame_control = unpack('H', self.raw_packet[self.PpiPacketHeader[2]:self.PpiPacketHeader[2]+2])[0] & 0xf6

    def __CheckFCS(self):
        """Return true when the FCS at the end of the frame is correct, i.e. the frame is not corrupted
        """
    	    
        crc32 = zlib.crc32(self.raw_packet[self.PpiPacketHeader[2]:-4])
        fcs = unpack('l', self.raw_packet[-4:])[0]
        return fcs == crc32
        
    def timestamp(self):
        gmt = time.gmtime(self.bpf_header[0])
        return ('%04d%02d%02d-%02d%02d%02d' % gmt[0:6]) + ('.%06d' % self.bpf_header[1])

class cPacketPR(cPacket):
    """Class to parse probe request packets
    """
    
    def __init__(self, bpf_header, raw_packet):
        super(cPacketPR, self).__init__(bpf_header, raw_packet)
        self.MAC = None
        self.SSID = None
        if self.frame_control == 0x40:
            fmt_ph = 'HH6s6s6sH' # frame_control duration DA SA ID sequence
            probe_header = unpack(fmt_ph, self.raw_packet[self.PpiPacketHeader[2]:self.PpiPacketHeader[2]+calcsize(fmt_ph)])
            parameters = self.raw_packet[self.PpiPacketHeader[2]+calcsize(fmt_ph):]
            fmt_prm = 'BB' # tag_number tag_length
            parameter = unpack(fmt_prm, parameters[0:calcsize(fmt_prm)])
            if parameter[0] == 0 and parameter[1] > 0 and parameter[1] < 33:
                self.MAC = ''.join([('%02X' % ord(c)) for c in probe_header[3]])
                self.SSID = parameters[2:2+parameter[1]]
        
def Report(dPRData, oOUI, oExclude):
    """Generate probe request report
    """
    
    f = file(REPORT_FILE, 'w')
    for MAC in sorted(dPRData.keys()):
        if not oExclude.test(MAC):
            organisation = oOUI.lookup(MAC)
            if organisation != '':
                organisation = ' ' + organisation
            print >> f, '%s %s %s%s' % (MAC, dPRData[MAC].firstseen, dPRData[MAC].lastseen, organisation)
            for day in sorted(dPRData[MAC].packets):
                print >> f, '  %s %d' % (day, dPRData[MAC].packets[day])
            for SSID in sorted(dPRData[MAC].SSIDs):
                print >> f, '  ' + repr(SSID)
    f.close()

class cOUI:
    """class to parse oui.txt file and lookup OUI
    """
    
    def __init__(self, filename):
        self.OUI = {}
        if os.path.exists(filename):
            reOUI = re.compile('([0-9A-F]+)\s+\(base 16\)\s+(.+)')
            f = open(filename, 'r')
            for line in f:
                oMatch = reOUI.match(line)
                if oMatch:
                    self.OUI[oMatch.group(1)] = oMatch.group(2)
            f.close()
    
    def lookup(self, MAC):
        if MAC[:6].upper() in self.OUI:
            return self.OUI[MAC[:6].upper()]
        else:
            return ''

def Main():
    """Tool to log WiFi probe requests
    """
    
    parser = OptionParser(usage='usage: %prog [options]', version='%prog 0.1')
    parser.add_option('-e', '--nonewssids', action='store_true', default=False, help="don't print new SSIDs")
    parser.add_option('-c', '--nonewclients', action='store_true', default=False, help="don't print new clients")
    parser.add_option('-r', '--resume', action='store_true', default=False, help='resume logging')
    parser.add_option('-l', '--nolog', action='store_true', default=False, help="don't log each probe request")
    parser.add_option('-x', '--exclude', help='file with clients/OUIs to exclude from display and report')
    parser.add_option('-i', '--interval', default='0.5', type='float', help='interval in seconds between channel hops')
    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.print_help()
        print ''
        print '  Tool to log WiFi probe requests'
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'
    
    else:
        ca = create_string_buffer(AIRPCAP_ADAPTER)
        ce = create_string_buffer(AIRPCAP_ERRBUF_SIZE)

        hAPC = cdll.airpcap.AirpcapOpen(ca.raw, ce)

        if hAPC == 0:
            print 'Error opening adapter: %s' % repr(ce.raw)
            return
    
        cdll.airpcap.AirpcapTurnLedOff(hAPC, 0)

        if cdll.airpcap.AirpcapSetLinkType(hAPC, AIRPCAP_LT_802_11_PLUS_PPI) == 0:
            print 'Error AirpcapSetLinkType %s' % cdll.airpcap.AirpcapGetLastError(hAPC)
            cdll.airpcap.AirpcapClose(hAPC)
            return

        oChannel = cChannel()
        oChannel.step = 5
        
        if cdll.airpcap.AirpcapSetDeviceChannel(hAPC, oChannel.channel()) == 0:
            print 'Error AirpcapSetDeviceChannel %s' % cdll.airpcap.AirpcapGetLastError(hAPC)
            cdll.airpcap.AirpcapClose(hAPC)
            return

        hRead = c_long(0)

        if cdll.airpcap.AirpcapGetReadEvent(hAPC, pointer(hRead)) == 0:
            print 'Error AirpcapGetReadEvent %s' % cdll.airpcap.AirpcapGetLastError(hAPC)
            cdll.airpcap.AirpcapClose(hAPC)
            return

        c_PacketBuffer = create_string_buffer(AIRPCAP_READ_BUFFER_SIZE)
        BytesReceived = c_long(0)

        dSSIDs = {}
        dMACs = {}
        dPRData = {}

        if options.resume and os.path.exists(PICKLE_FILE):
            print 'Loading %s' % PICKLE_FILE
            fPickle = open(PICKLE_FILE, 'rb')
            dPRData = pickle.load(fPickle)
            fPickle.close()
            for MAC in dPRData:
                if not MAC in dMACs:
                    dMACs[MAC]=1
                for SSID in dPRData[MAC].SSIDs:
                    if not SSID in dSSIDs:
                        dSSIDs[SSID]=1

        oOUI = cOUI(OUI_FILE)

        oExclude = cExclude(options.exclude)
                
        try:
            while True:
                # read captures and store in captures list
                if cdll.airpcap.AirpcapRead(hAPC, c_PacketBuffer, AIRPCAP_READ_BUFFER_SIZE, pointer(BytesReceived)) == 0:
                    print 'Error AirpcapRead %s' % cdll.airpcap.AirpcapGetLastError(hAPC)
                    cdll.airpcap.AirpcapClose(hAPC)
                    return
                captures = []
                if BytesReceived.value > 0:
                    index = 0
                    while index < BytesReceived.value:
                        bpf_header = unpack('LLLLH', c_PacketBuffer.raw[index:index+18])
                        captures.append([bpf_header, c_PacketBuffer.raw[index+bpf_header[4]:index+bpf_header[4]+bpf_header[2]]])
                        # calculate index next capture
                        index = index + bpf_header[4]
                        if bpf_header[2] % 4 == 0:
                            index = index + bpf_header[2]
                        else:
                            index = index + (bpf_header[2] / 4 + 1) * 4
                            
                # parse captures
                for capture in captures:
                    oPacketPR = cPacketPR(capture[0], capture[1])
                    if oPacketPR.SSID != None:
                        log = '%s %s %s' % (oPacketPR.timestamp(), oPacketPR.MAC, repr(oPacketPR.SSID))
                        if not options.nonewclients and not oPacketPR.MAC in dMACs and not oExclude.test(oPacketPR.MAC):
                            print '%s New MAC %s %s' % (oPacketPR.timestamp(), oPacketPR.MAC, oOUI.lookup(oPacketPR.MAC))
                            dMACs[oPacketPR.MAC]=1
                        if not options.nonewssids and not oPacketPR.SSID in dSSIDs and not oExclude.test(oPacketPR.MAC):
                            print '%s New SSID %s' % (oPacketPR.timestamp(), repr(oPacketPR.SSID))
                            dSSIDs[oPacketPR.SSID]=1
                        if not options.nolog:
                            logfile = open(LOG_FILE, 'a')
                            print >> logfile, log
                            logfile.close()
                        if oPacketPR.MAC in dPRData:
                            dPRData[oPacketPR.MAC].add(oPacketPR.timestamp(), oPacketPR.SSID)
                        else:
                            dPRData[oPacketPR.MAC] = cPRData(oPacketPR.MAC, oPacketPR.timestamp(), oPacketPR.SSID)
                
                # write report each time we looped through all the channels
                if oChannel.channel() == 1:
                    Report(dPRData, oOUI, oExclude)

                # hop channel
                oChannel.next()
                if cdll.airpcap.AirpcapSetDeviceChannel(hAPC, oChannel.channel()) == 0:
                    print 'Error AirpcapSetDeviceChannel %s' % cdll.airpcap.AirpcapGetLastError(hAPC)
                    cdll.airpcap.AirpcapClose(hAPC)
                    return
                time.sleep(options.interval)
                
        except KeyboardInterrupt:    
            print 'Interrupted by user'
            Report(dPRData, oOUI, oExclude)
            fPickle = open(PICKLE_FILE, 'wb')
            pickle.dump(dPRData, fPickle)
            fPickle.close()

        cdll.airpcap.AirpcapClose(hAPC)

if __name__ == '__main__':
    Main()
