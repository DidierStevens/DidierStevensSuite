#!/usr/bin/env python

__description__ = 'jumplist plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/05/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/04/14: start
  2015/05/11: added option -f
  2015/05/12: continue

Todo:
"""

import struct
import datetime
import binascii
import uuid

class cJumpList(cPluginParent):
    macroOnly = False
    name = 'jumplist plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

# http://articles.forensicfocus.com/2012/10/30/forensic-analysis-of-windows-7-jump-lists/
    def Analyze(self):
        result = []
        fullOutput = self.options != '-f'
        if self.streamname == ['DestList']:
            self.ran = True
            stream = self.stream
            headerFormat = 'IIIfQQ'
            formatsize = struct.calcsize(headerFormat)
            firstIssuedEntryID, totalNumberCurrentEntries, totalNumberPinnedEntries, float, lastIssuedEntryID, numberOfActions = struct.unpack(headerFormat, stream[:formatsize])
            stream = stream[formatsize:]
            if fullOutput:
                result.append('First Issued Entry ID: %d' % firstIssuedEntryID)
                result.append('Total number of current entries in Jump List: %d' % totalNumberCurrentEntries)
                result.append('Total number of pinned entries: %d' % totalNumberPinnedEntries)
                result.append('Floating point value. Some kind of counter: %f' % float)
                result.append('Last issued Entry ID number: %d' % lastIssuedEntryID)
                result.append('Number of add/delete actions: %d' % numberOfActions)
                result.append('')
                result.append('Entries:')
            while len(stream) > 114:
                if fullOutput:
                    checksum = struct.unpack('Q', stream[0:8])[0]
                    newVolumeID = stream[8:24]
                    objectID1 = stream[24:40]
                    birthVolumeID = stream[40:56]
                    objectID2 = stream[56:72]
                    netbiosName = stream[72:88]
                    entryID = struct.unpack('Q', stream[88:96])[0]
                    floatAccess = struct.unpack('f', stream[96:100])[0]
                    msfiletime = struct.unpack('Q', stream[100:108])[0]
                    entryPinStatus = struct.unpack('I', stream[108:112])[0]

                    result.append('')
                    result.append(' Checksum: %x' % checksum)
                    result.append(' New volume ID: %s' % binascii.b2a_hex(newVolumeID))
                    result.append(' New volume ID: %s' % uuid.UUID(bytes=newVolumeID))
                    result.append(' Object ID 1: %s' % binascii.b2a_hex(objectID1))
                    result.append(' Birth volume ID: %s' % binascii.b2a_hex(birthVolumeID))
                    result.append(' Object ID 2: %s' % binascii.b2a_hex(objectID2))
                    result.append(' Netbios Name: %s' % netbiosName.rstrip('\0'))
                    result.append(' Entry ID number: %d' % entryID)
                    result.append(' Floating point access counter: %f' % floatAccess)
                    result.append(' Filetime: ' + (datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(microseconds=msfiletime/10)).isoformat())
                    result.append(' Entry Pin status: %d' % entryPinStatus)
                stream = stream[112:]
                size = struct.unpack('H', stream[:2])[0]
                stream = stream[2:]
                if fullOutput:
                    result.append(' Filename: ' + stream[:size * 2].decode('utf-16'))
                else:
                    result.append(stream[:size * 2].decode('utf-16'))
                stream = stream[size * 2:]
            if len(stream) > 0:
                if fullOutput:
                    result.append('')
                    result.append('Remaining bytes: %d' % len(stream))

        return result

AddPlugin(cJumpList)
