#!/usr/bin/env python

__description__ = 'HYPERLINK plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2025/05/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2025/05/04: start

Todo:
"""

class cHYPERLINK(cPluginParentOle):
    name = 'HYPERLINK plugin'

    def PreProcess(self):
        self.urls = set()

    def Process(self, name, stream):
        for url in re.findall(b'HYPERLINK "(.+?)"', stream):
            if not url in self.urls:
                print(url.decode())
                self.urls.add(url)

    def PostProcess(self):
        pass

AddPlugin(cHYPERLINK)
