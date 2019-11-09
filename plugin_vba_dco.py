#!/usr/bin/env python

__description__ = 'VBA declare/createobject plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/11/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/10/25: start
  2015/11/04: added keywords

Todo:
"""

import re

def ExtractFunction(line):
    if 'declare' in line.lower():
        oMatch = re.search(r'function\s+(\S+)\s+', line, re.I)
        if oMatch == None:
            return None
        return oMatch.group(1)
    else:
        return None

def ExtractVariable(line):
    if 'createobject' in line.lower():
        oMatch = re.search(r'(\S+)\s*=\s*CreateObject', line, re.I)
        if oMatch == None:
            return None
        return oMatch.group(1)
    else:
        return None

class cVBADCO(cPluginParent):
    macroOnly = True
    name = 'VBA DCO (Declare/CreateObject) plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        oREDCO = re.compile(r'\b(declare|createobject)\b', re.I)
        result = [line.strip() for line in self.stream.split('\n') if re.search(oREDCO, line) != None]
        keywords = []
        for line in result:
            keyword = ExtractFunction(line)
            if keyword != None and not keyword in keywords:
                keywords.append(keyword)
            keyword = ExtractVariable(line)
            if keyword != None and not keyword in keywords:
                keywords.append(keyword)
        keywordLines = [line.strip() for line in self.stream.split('\n') if [keyword for keyword in keywords if keyword.lower() in line.lower()] != []]
        if keywordLines != []:
            result.append('-' * 80)
            result.extend(keywordLines)
        return result

AddPlugin(cVBADCO)
