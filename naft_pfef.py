#!/usr/bin/env python

__description__ = 'Network Appliance Forensic Toolkit - Packet and Frame Extraction Functions'
__author__ = 'Didier Stevens'
__version__ = '0.0.7'
__date__ = '2013/10/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/11/30: start, refactoring from CiscoIOMemLL and ExtractIPPackets, sorted frames by address
  2012/02/16: V0.0.4: memory optimization
  2012/02/17: refactoring
  2012/02/20: V0.0.5: refactoring
  2012/02/23: added OUI.TXT filtering
  2013/10/12: V0.0.7: cFrames added dFilenameIndexLength logic for buffered reads

Todo:
"""

import struct
import hashlib
import re
import binascii

class cFrames():
    def __init__(self, ouiFilename=None):
        self.frames = []
        self.countFrames = 0
        self.countPackets = 0
        self.dHashes = {}
        self.ParseOUITXT(ouiFilename)
        self.dFilenameIndexLength = {}

    def AddFramePrivate(self, index, data, duplicates, filename=''):
        filenameIndexLength = '%s-%d-%d' % (filename, index, len(data))
        if filenameIndexLength in self.dFilenameIndexLength:
            return False
        self.dFilenameIndexLength[filenameIndexLength] = True
        sha1Hash = hashlib.sha1(data).hexdigest()
        if not sha1Hash in self.dHashes:
            self.dHashes[sha1Hash] = 0
        self.dHashes[sha1Hash] += 1
        if duplicates or self.dHashes[sha1Hash] == 1:
            self.frames.append((index, data))
        return True

    def AddFrame(self, index, data, duplicates, filename=''):
        if self.dOUI == {} or binascii.hexlify(data[0:3]) in self.dOUI or binascii.hexlify(data[6:9]) in self.dOUI:
            if self.AddFramePrivate(index, data, duplicates, filename):
                self.countFrames += 1

    def AddIPPacket(self, index, data, duplicates, filename=''):
        if self.AddFramePrivate(index, '\x00\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00' + '\x08\x00' + data, duplicates, filename):
            self.countPackets += 1

    def WritePCAP(self, filename):
        try:
            f = open(filename, 'wb')
        except:
            return False

        # Gloval header
        f.write('\xD4\xC3\xB2\xA1') # magic number
        f.write('\x02\x00')         # major version number
        f.write('\x04\x00')         # minor version number
        f.write('\x00\x00\x00\x00') # GMT to local correction
        f.write('\x00\x00\x00\x00') # accuracy of timestamps
        f.write('\xFF\xFF\x00\x00') # max length of captured packets, in octets
        f.write('\x01\x00\x00\x00') # data link type

        for frame in sorted(self.frames, key=lambda x: x[0]):
            # Packet Header 
            f.write(struct.pack('<I', frame[0] / 1000000))         # timestamp seconds; set to address
            f.write(struct.pack('<I', frame[0] % 1000000))         # timestamp microseconds; set to address
            f.write(struct.pack('<I', min(len(frame[1]), 0xFFFF))) # number of octets of packet saved in file; limit to 0xFFFF for WireShark
            f.write(struct.pack('<I', min(len(frame[1]), 0xFFFF))) # actual length of packet; limit to 0xFFFF for WireShark

            # Packet Data
            f.write(frame[1][0:0xFFFF])

        f.close()

        return True

    def Write010Template(self, filename):
        countUnknowns = 1
        countFrames = 1
        try:
            f = open(filename, 'w')
        except:
            return False

        f.write('// Generated\n')
        f.write('local int iCOLOR = 0x95E8FF; // Color used for highlighting\n')
        f.write('local int iToggleColor = iCOLOR;\n')
        f.write('void ToggleBackColor()\n')
        f.write('{\n')
        f.write('	if (iToggleColor == iCOLOR)\n')
        f.write('		iToggleColor = cNone;\n')
        f.write('	else\n')
        f.write('		iToggleColor = iCOLOR;\n')
        f.write('	SetBackColor(iToggleColor);\n')
        f.write('}\n')

        index = 0
        for frame in sorted(self.frames, key=lambda x: x[0]):
            if frame[0] > index:
                f.write('ToggleBackColor();\n')
                f.write('BYTE unknown%d[%d];\n' % (countUnknowns, frame[0] - index))
                countUnknowns += 1
                f.write('ToggleBackColor();\n')
                f.write('BYTE frame%d[%d];\n' % (countFrames, len(frame[1])))
                countFrames += 1
                index = frame[0] + len(frame[1])

        f.close()

        return True

    def ParseOUITXT(self, ouiFilename):
        self.dOUI = {}
        if ouiFilename != None:
            oRe = re.compile('^([0-9a-f]{6})')
            try:
                fOUI = open(ouiFilename, 'r')
            except:
                return
            for line in fOUI.readlines():
                oMatch = oRe.search(line.lower())
                if oMatch:
                    self.dOUI[oMatch.group(1)] = line.strip('\n')
            fOUI.close()

#http://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python
def CarryAroundAdd(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def CalculateIPChecksum(data):
    s = 0
    for i in range(0, len(data), 2):
        s = CarryAroundAdd(s, ord(data[i]) + (ord(data[i+1]) << 8))
    return ~s & 0xffff

# search for bytes between 0x45 and 0x4F (depending flag options) and check if they are the start op a IPv4 header by calculating and comparing the checksum
def ExtractIPPackets(oFrames, baseAddress, data, options, duplicates, multiple, filename=''):
    found = False
    if options:
        maxHeader = 0x50
    else:
        maxHeader = 0x46
    for headerStart in range(0x45, maxHeader):
        index = 0
        while index != -1:
            index = data.find(chr(headerStart), index)
            if index != -1:
                try:
                    potentialIPHeader = data[index:index + 4 * (ord(data[index]) - 0x40)]
                    if CalculateIPChecksum(potentialIPHeader) == 0:
                        packetLength = ord(potentialIPHeader[2]) * 0x100 + ord(potentialIPHeader[3])
                        if ord(data[index-2]) == 8 and ord(data[index-1]) == 0: # EtherType IP
                            # IPv4 packet is inside an Ethernet frame; store the Ethernet frame
                            if ord(data[index-6]) == 0x81 and ord(data[index-5]) == 0: # 802.1Q, assuming no double tagging
                                oFrames.AddFrame(baseAddress + index - 2*6 - 4 - 2, data[index - 2*6 - 4 - 2:index + packetLength], duplicates, filename)
                                found = True
                            else:
                                oFrames.AddFrame(baseAddress + index - 2*6 - 2, data[index - 2*6 - 2:index + packetLength], duplicates, filename)
                                found = True
                        else:
                            # IPv4 packet is not inside an Ethernet frame; store the IPv4 packet
                            oFrames.AddIPPacket(baseAddress + index, data[index:index + packetLength], duplicates, filename)
                            found = True
                except:
                    pass
                index += 1
            if found and not multiple:
                return found
    return found

# search for ARP frames for Ethernet, they start with \x08\x06\x00\x01\x08\x00\x06\x04
def ExtractARPFrames(oFrames, baseAddress, data, duplicates, multiple, filename=''):
    found = False
    index = 0
    while index != -1:
        index = data.find('\x08\x06\x00\x01\x08\x00\x06\x04', index) # https://en.wikipedia.org/wiki/Address_Resolution_Protocol
        if index != -1:
            oFrames.AddFrame(baseAddress + index - 2*6, data[index - 2*6:index + 30], duplicates, filename)
            found = True
            index += 1
        if found and not multiple:
            return found
    return found
