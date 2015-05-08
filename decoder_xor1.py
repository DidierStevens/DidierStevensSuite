#!/usr/bin/env python

__description__ = 'XOR 1 byte decoder for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2014/12/14'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/14: start

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
        decoded = ''.join([chr(ord(c) ^ self.keyXOR1) for c in self.stream])
        self.name = 'XOR 1 byte key 0x%02X' % self.keyXOR1
        self.keyXOR1 += 1
        return decoded

    def Name(self):
        return self.name

AddDecoder(cXOR1Decoder)
