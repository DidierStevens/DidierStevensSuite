#!/usr/bin/env python

__description__ = 'VBA routines (Sub and Function) plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/11/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/11/04: start

Todo:
"""

import re

class cVBAR(cPluginParent):
    macroOnly = True
    name = 'VBA Routines plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        oRER = re.compile(r'\s*(private\s+|public\s+)?(sub|function)\s+\S+', re.I)
        result = []
        for line in self.stream.split('\n'):
            line = line.rstrip('\r')
            if re.match(oRER, line):
                result.append('-' * 80)
            result.append(line)
        return result

AddPlugin(cVBAR)
