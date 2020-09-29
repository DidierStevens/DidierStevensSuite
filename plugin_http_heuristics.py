#!/usr/bin/env python

__description__ = 'HTTP Heuristics plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.13'
__date__ = '2020/08/16'

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
  2016/12/11: 0.0.9 added iOffset loop
  2018/10/13: 0.0.10 changed XOR logic, added options (-e -k)
  2019/11/05: 0.0.11 Python 3 support
  2020/01/24: 0.0.12 added option -c
  2020/01/25: Python 3 bugfix; deduping of result
  2020/08/16: 0.0.13 added option -s

Todo:
"""

import re
import binascii
import codecs

def ReplaceFunction(match):
    try:
        return '(%d)' % eval(match.group(0))
    except:
        return match.group(0)

keywords = ['http:', 'https:']
extendedkeywords = ['msxml', 'adodb', 'shell', 'c:\\', 'cmd', 'powershell']

def StartsWithHTTP(str):
    tosearch = str.lower()
    for keyword in keywords:
        if tosearch.startswith(keyword):
            return True
    return False

def ContainsHTTP(str):
    tosearch = str.lower()
    for keyword in keywords:
        if keyword in tosearch:
            return True
    return False

class cHTTPHeuristics(cPluginParent):
    macroOnly = True
    name = 'HTTP Heuristics plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.streamOriginal = stream
        self.stream = stream
        self.options = options
        self.ran = False
        self.CheckFunction = StartsWithHTTP

    def Heuristics(self, data, noDecode=False):
        if self.CheckFunction(data):
            return data
        if self.CheckFunction(data[::-1]):
            return data[::-1]
        if noDecode:
            return data
        try:
            decoded = binascii.a2b_hex(data).decode()
            return self.Heuristics(decoded, True)
        except:
            if not re.compile(r'^[0-9a-zA-Z/+=]+$').match(data):
                return data
            try:
                decoded = binascii.a2b_base64(data).decode()
                return self.Heuristics(decoded, True)
            except:
                return data

    # bruteforce XOR; if we have more than 250 strings, split in short strings (< 10) = keys and long strings = ciphertext
    def BruteforceDecode(self, strings):
        ciphertexts = []
        keys = []
        result = []

        if len(strings) >= 250:
            for string1 in strings:
                if len(string1) >= 10:
                    ciphertexts.append(string1)
                else:
                    keys.append(string1)
        else:
            ciphertexts = strings
            keys = strings
        for key in keys:
            if key != '':
                for ciphertext in ciphertexts:
                    for iOffset in range(2):
                        cleartext = ''
                        for iIter in range(len(ciphertext)):
                            cleartext += chr(ord(ciphertext[iIter]) ^ ord(key[(iIter + iOffset)% len(key)]))
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

    def PreProcess(self, options):
        self.stream = re.sub(r'(\(\s*(\d+|\d+\.\d+)\s*[+*/-]\s*(\d+|\d+\.\d+)\s*\))', ReplaceFunction, self.streamOriginal)
        
        if options.space:
            self.stream = self.stream.replace(' ', '')

    def AnalyzeSub(self):
        global keywords

        oParser = optparse.OptionParser()
        oParser.add_option('-e', '--extended', action='store_true', default=False, help='Use extended keywords')
        oParser.add_option('-k', '--keywords', type=str, default='', help='Provide keywords (separator is ,)')
        oParser.add_option('-c', '--contains', action='store_true', default=False, help='Check if string contains keyword')
        oParser.add_option('-s', '--space', action='store_true', default=False, help='Ignore space characters')
        (options, args) = oParser.parse_args(self.options.split(' '))

        self.PreProcess(options)

        if options.extended:
            keywords = keywords + extendedkeywords

        if options.keywords != '':
            keywords = options.keywords.split(',')

        if options.contains:
            self.CheckFunction = ContainsHTTP

        result = []

        oREChr = re.compile(r'((chr[w\$]?\(\d+\)(\s*&\s*)?)+)', re.IGNORECASE)
        oREDigits = re.compile(r'\d+')
        for foundTuple in oREChr.findall(self.stream.replace('_\r\n', '')):
            chrString = ''.join(map(lambda x: chr(int(x)), oREDigits.findall(foundTuple[0])))
            if chrString != '':
                result.append(self.Heuristics(chrString))

        oREHexBase64 = re.compile(r'"([0-9a-zA-Z/+=]+)"')
        for foundString in oREHexBase64.findall(self.stream):
            if foundString != '':
                    result.append(self.Heuristics(foundString))

        oREHTTP = re.compile(r'"(http[^"]+)"')
        for foundString in oREHTTP.findall(self.stream):
            if foundString != '':
                    result.append(foundString)

        resultHttp = [line for line in result if self.CheckFunction(line)]

        if resultHttp == []:
            resultHttp = [line for line in self.BruteforceDecode(result) if self.CheckFunction(line)]

        if resultHttp == []:
            resultHttp = [codecs.encode(line, 'rot-13') for line in self.Strings() if ContainsHTTP(codecs.encode(line, 'rot-13'))]
        else:
            return resultHttp

        if resultHttp == []:
            resultHttp = [line for line in self.StringsPerLine() if ContainsHTTP(line)]
        else:
            return resultHttp

        if resultHttp == []:
            return result
        else:
            return resultHttp

    def Analyze(self):
        self.ran = True

        return set(self.AnalyzeSub())

AddPlugin(cHTTPHeuristics)
