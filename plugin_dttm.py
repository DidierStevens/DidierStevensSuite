#!/usr/bin/env python

__description__ = 'Word DTTM date/time structure plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2022/11/09'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/10/09: start
  2022/11/09: added option --verbose

Todo:
"""

import bitstruct
import datetime
import collections

#https://interoperability.blob.core.windows.net/files/MS-DOC/%5bMS-DOC%5d.pdf

nDTTM = collections.namedtuple('nDTTM', ['valid', 'null', 'year', 'month', 'day', 'weekday', 'hours', 'minutes'])

def ParseDTTM(data):
    if data == b'\x00\x00\x00\x00':
        return nDTTM(True, True, 0, 0, 0, 0, 0, 0)
    inDTTM = nDTTM(False, False, 0, 0, 0, 0, 0, 0)
    weekday, year, month, day, hours, minutes = bitstruct.unpack('u3u9u4u5u5u6', data[::-1])
    if minutes > 0x3B or hours > 0x17 or day == 0 or day > 0x1F or month == 0 or month > 0x0C or weekday > 0x06:
        return inDTTM
    year += 1900
    try:
        oDatetime = datetime.datetime(year, month, day)
    except ValueError:
        return inDTTM
    weekdayCheck = oDatetime.weekday() + 1
    if weekdayCheck == 7:
        weekdayCheck = 0
    if weekdayCheck != weekday:
        return inDTTM
    return nDTTM(True, False, year, month, day, weekday, hours, minutes)

def PrintDTTM(inDTTM):
    if inDTTM.null:
        return 'null'
    dWeekdays = {
        0: 'Sun',
        1: 'Mon',
        2: 'Tue',
        3: 'Wed',
        4: 'Thu',
        5: 'Fri',
        6: 'Sat',
    }
    return '%04d/%02d/%02d(%s) %02d:%02d' % (inDTTM.year, inDTTM.month, inDTTM.day, dWeekdays[inDTTM.weekday], inDTTM.hours, inDTTM.minutes)

class cCLSID(cPluginParent):
    macroOnly = False
    name = 'OLE streams plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        oParser = optparse.OptionParser()
        oParser.add_option('--minyear', type=int, default=1900, help='Minimum year value (default 1900)')
        oParser.add_option('--maxyear', type=int, default=3000, help='Maximum year value (default 3000)')
        oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output')
        (options, args) = oParser.parse_args(self.options.split(' '))

        result = []
        self.ran = True
        stream = self.stream
        positionPotentialDOPs = []
        potentialPrevious = []

        dPrevious = {
            0x6805: 'sprmCDttmRMark',
            0x6864: 'sprmCDttmRMarkDel',
        }

        for iter in range(len(stream) - 4):
            data = self.stream[iter:iter + 4]
            inDTTM = ParseDTTM(data)
            if not inDTTM.valid:
                continue
            if inDTTM.null:
                continue
            if inDTTM.year < options.minyear or inDTTM.year > options.maxyear:
                continue
            if options.verbose:
                result.append('0x%08x: %s' % (iter, PrintDTTM(inDTTM)))
            if iter >= 2:
                previous = struct.unpack('<H', self.stream[iter - 2:iter])[0]
                if previous == 0x0000:
                    positionPotentialDOPs.append(iter)
                if previous in dPrevious:
                    potentialPrevious.append([previous, iter])

        validDOPs = []
        for position in positionPotentialDOPs:
            format = '<HIIIHI'
            lengthData = 3*4 + struct.calcsize(format)
            data = stream[position:position+lengthData]
            if len(data) != lengthData:
                continue
            dataCreated = data[:4]
            dataRevised = data[4:8]
            dataLastPrint = data[8:12]
            inDTTMCreated = ParseDTTM(dataCreated)
            inDTTMRevised = ParseDTTM(dataRevised)
            inDTTMLastPrint = ParseDTTM(dataLastPrint)
            if inDTTMCreated.valid and (inDTTMRevised.valid or inDTTMRevised.null) and (inDTTMLastPrint.valid or inDTTMLastPrint.null):
                validDOPs.append('Position DOP: 0x%08x' % position)
                validDOPs.append(' dttmCreated:   %s %s' % (PrintDTTM(inDTTMCreated), binascii.b2a_hex(dataCreated)))
                validDOPs.append(' dttmRevised:   %s %s' % (PrintDTTM(inDTTMRevised), binascii.b2a_hex(dataRevised)))
                validDOPs.append(' dttmLastPrint: %s %s' % (PrintDTTM(inDTTMLastPrint), binascii.b2a_hex(dataLastPrint)))
                metadata = struct.unpack(format, data[12:])
                validDOPs.append(' nRevision: %d' % metadata[0])
                validDOPs.append(' tmEdited: %d' % metadata[1])
                validDOPs.append(' cWords: %d' % metadata[2])
                validDOPs.append(' cCh: %d' % metadata[3])
                validDOPs.append(' cPg: %d' % metadata[4])
                validDOPs.append(' cParas: %d' % metadata[5])
        result.extend(validDOPs)

        previousOutput = []
        for previous, position in potentialPrevious:
            dataDTTM = stream[position:position+4]
            previousOutput.append(' %s: %s' % (dPrevious.get(previous, '0x%04x' % previous), PrintDTTM(ParseDTTM(dataDTTM))))

        if len(previousOutput) > 0:
            result.append('DTTMs:')
            result.extend(previousOutput)

        return result

AddPlugin(cCLSID)
