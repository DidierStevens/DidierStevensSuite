#!/usr/bin/env python

__description__ = 'String subtract plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/03/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/03/04: start

Todo:
"""

import re

def AllCharactersInStr(str1, str2):
    return all([c in str2 for c in str1])

class cStringSubtract(cPluginParent):
    macroOnly = True
    name = 'String subtract plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        allstrings = []
        result = []
        dDecodes = {}

        oREStr = re.compile(r'"[^"\n]+"')
        for found in oREStr.findall(self.stream.replace('_\r\n', '')):
            allstrings.append(found)
        for str1 in allstrings:
            for str2 in allstrings:
                if str1 != str2 and AllCharactersInStr(str1, str2):
                    if not str1 in dDecodes:
                        dDecodes[str1] = []
                    dDecodes[str1].append(''.join([c for c in str2 if not c in str1]))
                    
        for v, k in sorted([(len(v), k) for k, v in dDecodes.items()]):
            for s in dDecodes[k]:
                result.append(s)
        return result

AddPlugin(cStringSubtract)
