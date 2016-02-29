#!/usr/bin/env python

__description__ = 'Linear cryptanalysis plugin for oledump'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/12/26'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/12/02: start
  2015/12/26: fix aaa2 = Array(1111, ...


Todo:
"""

import re

class cLCA(cPluginParent):
    macroOnly = True
    name = 'Linear cryptanalysis'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        result = []
        oRE = re.compile('\d+')
        for line in self.stream.split('\n'):
            position = line.find('=')
            if position == -1:
                position = 0
            results = oRE.findall(line[position:])
            if len(results) >= 10:
                a = (ord('t') - int(results[1])) - (ord('h') - int(results[0]))
                b = (ord('h') - int(results[0]))
                decoded = ''
                try:
                    decoded = ''.join([chr(int(results[i]) + i*a + b) for i in range(len(results))])
                except:
                    pass
                if decoded.startswith('http'):
                    result.append(decoded)
        return result

AddPlugin(cLCA)
