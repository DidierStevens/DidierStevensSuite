#!/usr/bin/env python

__description__ = 'VBA summary plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2017/07/20'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/11: start
  2015/03/11: 0.0.2 stripping \r
  2017/07/20: 0.0.3 do not select end function, end sub, exit function, exit sub

Todo:
"""

class cVBASummary(cPluginParent):
    macroOnly = True
    name = 'VBA summary plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        return [line.strip('\r') for line in self.stream.split('\n') if ('"' in line or 'sub' in line.lower() or 'function' in line.lower()) and (not 'exit sub' in line.lower() and not 'exit function' in line.lower() and not 'end sub' == line.lower() and not 'end function' == line.lower())]

AddPlugin(cVBASummary)
