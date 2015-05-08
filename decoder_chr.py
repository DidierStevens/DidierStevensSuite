#!/usr/bin/env python

__description__ = 'CHR decoder for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2014/12/19'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/31: start

Todo:
"""

import re

class cCHRDecoder(cDecoderParent):
    name = 'CHR decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.done = False

    def Available(self):
        return not self.done

    def Decode(self):
        decoded = ''.join([chr(int(s[4:-1])) for s in re.compile('chr\(\d+\)', re.IGNORECASE).findall(SearchAndDecompress(self.stream))])
        self.name = 'CHR decoder'
        self.done = True
        return decoded

    def Name(self):
        return self.name

AddDecoder(cCHRDecoder)
