#!/usr/bin/env python

__description__ = 'OOXML URL plugin for myjson-filter.py'
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

import xml.dom.minidom

class cDOCXURL(cPluginParent):
    name = 'docxurl plugin'

    def __init__(self, options):
        self.options = options
        self.ran = False

    def PreProcess(self):
        self.urls = set()

    def Process(self, id, name, magic, data):
        try:
            root = xml.dom.minidom.parseString(data.decode())
        except Exception as e:
            return
        for relationship in root.getElementsByTagName('Relationship'):
            if 'Type' in relationship.attributes.keys() and 'Target' in relationship.attributes.keys() and relationship.attributes.get('Type').value == 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink':
                url = relationship.attributes.get('Target').value
                if not url in self.urls:
                    print(url)
                    self.urls.add(url)

    def PostProcess(self):
        self.ran = True

AddPlugin(cDOCXURL)
