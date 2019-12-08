#!/usr/bin/env python

__description__ = 'XOR 1 byte decoder for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2019/11/24'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/14: start
  2019/11/24: Python 3 fixes

Todo:
"""

def ParseNumber(number):
    if number.startswith('0x'):
        return int(number[2:], 16)
    else:
        return int(number)

class cXOR1Decoder(cDecoderParent):
    name = 'XOR 1 byte decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        if self.options.startswith('-k '):
            self.keyXOR1 = ParseNumber(self.options[3:])
        else:
            self.keyXOR1 = 0x01

    def Available(self):
        return self.keyXOR1 != 0x100

    def Decode(self):
        if sys.version_info[0] > 2:
            decoded = bytes([(c ^ self.keyXOR1) for c in self.stream])
        else:
            decoded = ''.join([chr(ord(c) ^ self.keyXOR1) for c in self.stream])
        self.name = 'XOR 1 byte key 0x%02X' % self.keyXOR1
        self.keyXOR1 += 1
        return decoded

    def Name(self):
        return self.name

AddDecoder(cXOR1Decoder)
