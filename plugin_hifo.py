#!/usr/bin/env python

__description__ = 'HTTP in Form /o plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/02/29'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/02/29: start

Todo:
"""

import re

class cFO(cPluginParent):
    macroOnly = False
    name = 'HTTP in Form /o plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if len(self.streamname) > 1 and self.streamname[-1] == 'o':
            self.ran = True
            for match in re.findall(r'http[\x21-\x7E]+', self.stream):
                result.append(match)

        return result

AddPlugin(cFO)
