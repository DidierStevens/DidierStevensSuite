#!/usr/bin/env python

__description__ = 'HTTP Heuristics plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.8'
__date__ = '2015/04/01'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/11/12: start
  2014/11/13: added HTTP filter
  2014/11/14: added unencoded http string detection
  2014/11/15: changed name and plugin interface
  2014/11/21: changed interface: added options
  2014/12/12: added BruteforceDecode
  2015/02/02: 0.0.3 added base64
  2015/02/09: bugfix BruteforceDecode when empty string; added StringsPerLine
  2015/02/16: 0.0.4 added rot13
  2015/02/25: 0.0.5 joined lines ending with _ for Chr analysis
  2015/03/18: 0.0.6 also handle empty strings
  2015/03/23: 0.0.7 fixed regression bug Heuristics
  2015/04/01: 0.0.8 added PreProcess

Todo:
"""

import re
import binascii

def ReplaceFunction(match):
    try:
        return '(%d)' % eval(match.group(0))
    except:
        return match.group(0)

class cHTTPHeuristics(cPluginParent):
    macroOnly = True
    name = 'HTTP Heuristics plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.streamOriginal = stream
        self.stream = stream
        self.options = options
        self.ran = False

    def Heuristics(self, data, noDecode=False):
        if data.lower().startswith('http:'):
            return data
        if data[::-1].lower().startswith('http:'):
            return data[::-1]
        if noDecode:
            return data
        try:
            decoded = binascii.a2b_hex(data)
            return self.Heuristics(decoded, True)
        except:
            if not re.compile(r'^[0-9a-zA-Z/=]+$').match(data):
                return data
            try:
                decoded = binascii.a2b_base64(data)
                return self.Heuristics(decoded, True)
            except:
                return data

    # bruteforce XOR; short strings (< 10) are keys
    def BruteforceDecode(self, strings):
        ciphertexts = []
        keys = []
        result = []

        for string1 in strings:
            if len(string1) >= 10:
                ciphertexts.append(string1)
            else:
                keys.append(string1)

        for key in keys:
            if key != '':
                for ciphertext in ciphertexts:
                    cleartext = ''
                    for iIter in range(len(ciphertext)):
                        cleartext += chr(ord(ciphertext[iIter]) ^ ord(key[iIter % len(key)]))
                    result.append(self.Heuristics(cleartext))

        return result

    def Strings(self):
        return re.compile(r'"([^"]+)"').findall(self.stream)

    # Concatenate all strings found on the same line
    def StringsPerLine(self):
        result = []
        oREString = re.compile(r'"([^"]*)"')

        for line in self.stream.split('\n'):
            stringsConcatenated = ''.join(oREString.findall(line))
            if stringsConcatenated != '':
                result.append(stringsConcatenated)

        return result

    def PreProcess(self):
        self.stream = re.sub(r'(\(\s*(\d+|\d+\.\d+)\s*[+*/-]\s*(\d+|\d+\.\d+)\s*\))', ReplaceFunction, self.streamOriginal)

    def Analyze(self):
        self.ran = True
        self.PreProcess()

        result = []

        oREChr = re.compile(r'((chr[w\$]?\(\d+\)(\s*&\s*)?)+)', re.IGNORECASE)
        oREDigits = re.compile(r'\d+')
        for foundTuple in oREChr.findall(self.stream.replace('_\r\n', '')):
            chrString = ''.join(map(lambda x: chr(int(x)), oREDigits.findall(foundTuple[0])))
            if chrString != '':
                result.append(self.Heuristics(chrString))

        oREHexBase64 = re.compile(r'"([0-9a-zA-Z/=]+)"')
        for foundString in oREHexBase64.findall(self.stream):
            if foundString != '':
                    result.append(self.Heuristics(foundString))

        oREHTTP = re.compile(r'"(http[^"]+)"')
        for foundString in oREHTTP.findall(self.stream):
            if foundString != '':
                    result.append(foundString)

        resultHttp = [line for line in result if line.lower().startswith('http:')]

        if resultHttp == []:
            resultHttp = [line for line in self.BruteforceDecode(result) if line.lower().startswith('http:')]

        if resultHttp == []:
            resultHttp = [line.decode('rot13') for line in self.Strings() if 'http:' in line.decode('rot13').lower()]
        else:
            return resultHttp

        if resultHttp == []:
            resultHttp = [line for line in self.StringsPerLine() if 'http:' in line.lower()]
        else:
            return resultHttp

        if resultHttp == []:
            return result
        else:
            return resultHttp

AddPlugin(cHTTPHeuristics)
