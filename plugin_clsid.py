#!/usr/bin/env python

__description__ = 'CLSID plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2020/03/06'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/03/06: start

Todo:
"""

def GUIDToBytes(clsid):
    parts = [binascii.a2b_hex(part) for part in clsid.split('-')]
    return parts[0][::-1] + parts[1][::-1] + parts[2][::-1] + parts[3] + parts[4] 

class cCLSID(cPluginParent):
    macroOnly = False
    name = 'CLSID plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []
        self.ran = True
        stream = self.stream

        if KNOWN_CLSIDS == {}:
            result.append('<oletools missing>')
        for clsid, desc in KNOWN_CLSIDS.items():
            for position in FindAll(stream, GUIDToBytes(clsid)):
                result.append('0x%08x %s %s' % (position, clsid, desc))

        return sorted(result)

AddPlugin(cCLSID)
