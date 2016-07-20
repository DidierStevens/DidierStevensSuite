#!/usr/bin/env python

__description__ = '/o plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/04/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/04/16: start

Todo:
"""

import struct

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
            while len(self.stream) > 0:
                code, length = struct.unpack("<HH", self.stream[0:4])
                if code == 0x200:
                    fieldtype = struct.unpack("<I", self.stream[4:8])[0]
                    if fieldtype == 0x80400101:
                        lengthString = struct.unpack("<I", self.stream[0x10:0x14])[0] & 0x7FFFFFFF
                        if self.options == '-d':
                            result.append('%04x %04x %08x %s' % (code, length, fieldtype, self.stream[0x1C:0x1C + lengthString]))
                        else:
                            result.append(self.stream[0x1C:0x1C + lengthString])
                    else:
                        if self.options == '-d':
                            result.append('%04x %04x %08x' % (code, length, fieldtype))
                else:
                    if self.options == '-d':
                        result.append('%04x %04x' % (code, length))
                self.stream = self.stream[4 + length:]

        return result

AddPlugin(cFO)
