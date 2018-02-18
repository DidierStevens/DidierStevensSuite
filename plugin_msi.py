#!/usr/bin/env python

__description__ = 'msi plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2018/02/18'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2018/02/18: start

Todo:
"""

import binascii
import hashlib

#https://stackoverflow.com/questions/9734978/view-msi-strings-in-binary

def Convert(character):
    code = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._!'
    number = ord(character)
    if number >= 0x3800 and number < 0x4800:
        return code[(number - 0x3800) & 0x3F] + code[((number - 0x3800) >> 6) & 0x3F]
    elif number >= 0x4800 and number <= 0x4840:
        return code[number - 0x4800]
    else:
        return character

class cMSI(cPluginParent):
    macroOnly = False
    name = 'msi plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True
        result = []
        result.append('%s %-16s %s' % ((repr('/'.join(map(lambda x: ''.join([Convert(y) for y in x.decode('utf8')]), self.streamname))) + ' ' * 100)[0:30], ''.join([IFF(ord(b) >= 32 and ord(b) < 127, b, '.') for b in self.stream[:16]]), hashlib.md5(self.stream).hexdigest()))

        return result

AddPlugin(cMSI)
