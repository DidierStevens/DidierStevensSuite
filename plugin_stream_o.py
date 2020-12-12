#!/usr/bin/env python

__description__ = '/o plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2020/12/10'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/04/16: start
  2020/12/10: 0.0.2 refactoring

Todo:
"""

import struct

def Unpack(format, data):
    size = struct.calcsize(format)
    if len(data) < size:
        return None
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

class cFO(cPluginParent):
    macroOnly = False
    name = 'UserForm /o plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if len(self.streamname) > 1 and self.streamname[-1] == 'o':
            self.ran = True
            data = self.stream
            foundCounter = 0
            while len(data) > 0:
                unpacked = Unpack('<HH', data)
                if unpacked == None:
                    break
                code, length, data = unpacked
                extraLength = 0
                if code == 0x200:
                    unpacked = Unpack('<I', data)
                    if result == unpacked:
                        break
                    fieldtype, remainder = unpacked
                    if fieldtype == 0x80400101:
                        foundCounter += 1
                        lengthString = struct.unpack("<I", remainder[0x08:0x0C])[0] & 0x7FFFFFFF
                        if lengthString % 4 == 0:
                            extraLength = lengthString
                        else:
                            extraLength = lengthString + 4 - lengthString % 4
                        if self.options == '-d':
                            result.append('%04x %04x %08x %s' % (code, length, fieldtype, remainder[0x14:0x14 + lengthString]))
                        else:
                            result.append(remainder[0x14:0x14 + lengthString].decode())
                    else:
                        if self.options == '-d':
                            result.append('%04x %04x %08x' % (code, length, fieldtype))
                else:
                    if self.options == '-d':
                        result.append('%04x %04x' % (code, length))
                data = data[length + extraLength:]

            if foundCounter > 1:
                result = ['Found: %d' % foundCounter] + result

        return result

AddPlugin(cFO)
