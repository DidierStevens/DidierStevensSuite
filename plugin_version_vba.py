#!/usr/bin/env python

__description__ = 'plugin to detect VBA version of ole Office documents'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2019/12/09'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2019/12/09: start

Todo:
"""

import struct

dVersions = {
    0x0004: 'Office 95',
    0x0073: 'Office XP',
    0x0079: 'Office 2003',
    0x0085: 'Office 2007',
    0x0097: 'Office 2010 32-bit/64-bit',
    0x00A3: 'Office 2013 32-bit',
    0x00A6: 'Office 2013 64-bit',
    0x00AF: 'Office 2016/2019 32-bit',
    0x00B2: 'Office 2016/2019 64-bit',
}

class cVV(cPluginParent):
    macroOnly = False
    name = 'version VBA plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if len(self.streamname) > 1 and self.streamname[-1].upper() == '_VBA_PROJECT':
            self.ran = True
            if len(self.stream) >= 4:
                code, version = struct.unpack("<HH", self.stream[0:4])
                line = '%04x: %s' % (version, dVersions.get(version, '?'))
                if code != 0x61CC:
                    line += ' Warning: stream starts with %04x' % code
                result.append(line)

        return result

AddPlugin(cVV)
