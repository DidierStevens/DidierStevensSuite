#!/usr/bin/env python

__description__ = 'VBA declare/createobject plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2019/11/25'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/10/25: start
  2015/11/04: added keywords
  2019/11/25: 0.0.3 update for GetObject, Callbyname and Shell

Todo:
"""

import re

def ContainsString(stringsToFind, containingString):
    containingString = containingString.lower()
    for stringToFind in stringsToFind:
        if stringToFind.lower() in containingString:
            return True
    return False
            
def ExtractDeclareFunctionSub(line):
    if ContainsString(['declare'], line):
        oMatch = re.search(r'(function|sub)\s+(\S+)\s+', line, re.I)
        if oMatch == None:
            return None
        return oMatch.group(2)
    else:
        return None

def ExtractSetObjectVariable(line):
    if ContainsString(['createobject', 'getobject'], line):
        oMatch = re.search(r'(\S+)\s*=\s*(CreateObject|GetObject)', line, re.I)
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

        oREDCO = re.compile(r'\b(declare|createobject|getobject|callbyname|shell)\b', re.I)
        result = [line.strip() for line in self.stream.split('\n') if re.search(oREDCO, line) != None]
        keywords = []
        for line in result:
            keyword = ExtractDeclareFunctionSub(line)
            if keyword != None and not keyword in keywords:
                keywords.append(keyword)
            keyword = ExtractSetObjectVariable(line)
            if keyword != None and not keyword in keywords:
                keywords.append(keyword)
        keywordLines = [line.strip() for line in self.stream.split('\n') if ContainsString(keywords, line)]
        if keywordLines != []:
            result.append('-' * 80)
            result.extend(keywordLines)
        return result

AddPlugin(cVBADCO)
