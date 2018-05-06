#!/usr/bin/env python

__description__ = 'Office crypto plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2018/05/06'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2018/05/06: start

Todo:
"""

import struct

class cOfficeCrypto(cPluginParent):
    macroOnly = False
    name = 'Office crypto plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if self.streamname == ['EncryptionInfo']:
            self.ran = True
            if len(self.stream) >= 4:
                dVersions = {'2.2': 'Standard Encryption', '3.2': 'Standard Encryption', '4.2': 'Standard Encryption', '3.3': 'Extensible Encryption', '4.3': 'Extensible Encryption', '4.4': 'Agile Encryption'}
                versionMajor, versionMinor = struct.unpack("<HH", self.stream[0:4])
                version = '%d.%d' % (versionMajor, versionMinor)
                result.append('Crypto version %s: %s' % (version, dVersions.get(version, 'Unknown')))
            else:
                result.append('EncryptionInfo stream is too short')

        return result

AddPlugin(cOfficeCrypto)
