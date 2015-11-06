#!/usr/bin/env python

__description__ = 'Dridex plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.9'
__date__ = '2015/11/06'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/02/12: start, based on sample 6beaa39b2a1d3d896c5e2fd277c227dd
  2015/02/16: added OlFdL0IOXbF, based on sample f1c80a738722554b91452c59adb2f27d
  2015/02/19: added NewQkeTzIIHM, based on sample d927f8cff07f87c3c3f748604ab35896
  2015/02/25: 0.0.4 added Xor FF, based on sample f3c3fbeed637cccc7549636b7e0f7cdb
  2015/02/26: 0.0.5 added Step2, based on sample 33c5ad38ad766d4e748ee3752fc4c292
  2015/04/08: 0.0.6 added KALLKKKASKAJJAS, based on sample 491A146F5DE3592C7D959E2869F259EF
  2015/04/09: 0.0.7 used KALLKKKASKAJJAS, based on sample 14C2795BCC35C3180649494EC2BC7877
  2015/04/08: 0.0.8 added GQQSfwKSTdAvZbHNhpfK, based on sample 39B38CE4E2E8D843F88C3DF9124527FC
  2015/11/06: 0.0.9 added chr support; added IpkfHKQ2Sd, based on sample 0E73D64FBDF6C87935C0CFF9E65FA3BE

Todo:
"""

import re
import binascii
import array

def RoV(InputStringToBeDecrypted):
    strTempText = InputStringToBeDecrypted
    strText = strTempText
    strDecryptedText = ""
    strText = strText[:len(strText) - 4]
    strText = strText[-(len(strText) - 4):]
    strText, nCharSize = Extract_Char_Size(strText)
    strText, nEncKey = Extract_Enc_Key(strText, nCharSize)
    nTextLenght = len(strText)
    for nCounter in range(0, len(strText), nCharSize):
        strChar1 = strText[nCounter:nCounter + nCharSize]
        nChar = aYP(strChar1)
        nChar2 = nChar / nEncKey
        strChar2 = chr(nChar2)
        strDecryptedText = strDecryptedText + strChar2
    return strDecryptedText.strip()

def Extract_Char_Size(strText):
    nLeft = len(strText) / 2
    strLeft = strText[:nLeft]
    nRight = len(strText) - nLeft
    strRight = strText[-nRight:]
    strKeyEnc = strLeft[-2:]
    strKeySize = strRight[:2]
    strKeyEnc = yiK(strKeyEnc)
    strKeySize = yiK(strKeySize)
    nKeyEnc = int(strKeyEnc)
    nKeySize = int(strKeySize)
    nCharSize = nKeySize - nKeyEnc
    strText = strLeft[:len(strLeft) - 2] + strRight[-(len(strRight) - 2):]
    return (strText, nCharSize)

def yiK(cString):
    strTempString = ""
    for strChar1 in cString:
        if strChar1.isdigit():
            strTempString = strTempString + strChar1
        else:
            strTempString = strTempString + "0"
    return strTempString

def aYP(strTempText):
    strText = ""
    strTempText = strTempText.strip()
    for strChar1 in strTempText:
        if strChar1.isdigit():
            strText = strText + strChar1
    return int(strText)

def Extract_Enc_Key(strText, nCharSize):
    strEncKey = ""
    nLenght = len(strText) - nCharSize
    nLeft = nLenght / 2
    strLeft = strText[:nLeft]
    nRight = nLenght - nLeft
    strRight = strText[-nRight:]
    strEncKey = strText[nLeft:nLeft + nCharSize]
    strEncKey = yiK(strEncKey)
    nEncKey = int(strEncKey.strip())
    strText = strLeft + strRight
    return (strText, nEncKey)

def MakePositive(value1, value2):
    while value1 < 0:
        value1 += value2
    return value1

def OlFdL0IOXbF(InputData, NumKey):
    return ''.join([chr(MakePositive(ord(c), 256) - NumKey) for c in InputData])

def NewQkeTzIIHM(InputData):
    return ''.join([chr(ord(c) - 13) for c in InputData])

def lqjWjFO(strData, strKey):
    result = ''
    for iIter in range(len(strData)):
        if iIter < len(strKey):
            result += chr(ord(strData[iIter]) - ord(strKey[iIter]))
        else:
            result += chr(ord(strData[iIter]) - ord(strKey[iIter % (len(strKey) - 1)]))
    return result

def Xor(data, key):
    return ''.join([chr(ord(c) ^ key) for c in data])

def Step(data, step):
    result = ''
    for iIter in range(0, len(data), step):
        result += data[iIter]
    return result

def ContainsString(listStrings, key):
    for aString in listStrings:
        if key.lower() in aString.lower():
            return True
    return False

def IsHex(value):
    return re.match(r'^([0-9a-f][0-9a-f])+$', value, re.IGNORECASE) != None

def KALLKKKASKAJJAS(strKey, strData):
    result = ''
    encoded = binascii.a2b_hex(strData)
    for iIter in range(len(encoded)):
        result += chr(ord(encoded[iIter]) ^ ord(strKey[(((iIter + 1) % len(strKey)))]))
    return result

def GQQSfwKSTdAvZbHNhpfK(strData, strKey):
    result = ''
    dX = {x:0 for x in range(256)}
    Y = 0
    for iIter in range(256):
        Y = (Y + dX[iIter] + ord(strKey[iIter % len(strKey)])) % 256
        dX[iIter] = iIter
    for iIter in range(len(strData)):
        Y = (Y + dX[Y] + 1) % 256
        result += chr(ord(strData[iIter]) ^ dX[dX[(Y + dX[Y]) % 254]])

    return result

def IpkfHKQ2Sd(secret, key):
    aTable = array.array('i', [0] * (285 + 1))
    aSecret = array.array('i', [0] * len(secret))
    keyLength = len(key) - 1
    for iIter in range(0, 255 + 1):
        aTable[iIter] = iIter
    for iIter in range(256, 285 + 1):
        aTable[iIter] = iIter ^ 256
    for iIter in range(1, 6 + 1):
        aTable[iIter + 249] = ord(key[keyLength - iIter])
        aTable[iIter - 1] = ord(key[iIter - 1]) ^ (255 - ord(key[keyLength - iIter]))

    bCondition = False
    indexKey = 0
    indexTable = 0
    for iIter in range(0, len(secret) - 1 + 1):
        if indexKey > keyLength:
            indexKey = 0
        if indexTable > 285 and bCondition == False:
            indexTable = 0
            bCondition = not bCondition
        if indexTable > 285 and bCondition == True:
            indexTable = 5
            bCondition = not bCondition
        aSecret[iIter] = ord(secret[iIter]) ^ (aTable[indexTable] ^ ord(key[indexKey]))
        indexKey = indexKey + 1
        indexTable = indexTable + 1
    return ''.join(map(chr, aSecret))

class cDridexDecoder(cPluginParent):
    macroOnly = True
    name = 'Dridex decoder'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        self.ran = True

        oREString = re.compile(r'"([^"\n]+)"')
        foundStrings = oREString.findall(self.stream)
        oREChr = re.compile(r'((chr[w\$]?\(\d+\)(\s*[&+]\s*)?)+)', re.IGNORECASE)
        oREDigits = re.compile(r'\d+')
        for foundTuple in oREChr.findall(self.stream.replace('_\r\n', '')):
            chrString = ''.join(map(lambda x: chr(int(x)), oREDigits.findall(foundTuple[0])))
            if chrString != '':
                foundStrings.append(chrString)

        for DecodingFunction in [RoV, lambda s:OlFdL0IOXbF(s, 61), NewQkeTzIIHM, lambda s:Xor(s, 0xFF), lambda s:Step(s, 2)]:
            result = []
            for foundString in foundStrings:
                try:
                    result.append(DecodingFunction(foundString))
                except:
                    pass

            if ContainsString(result, 'http'):
                return result

        foundStringsSmall = [foundString for foundString in foundStrings if len(foundString) <= 10]
        foundStringsLarge = [foundString for foundString in foundStrings if len(foundString) > 10]
        for foundStringSmall in foundStringsSmall:
            for DecodingFunction in [lqjWjFO, GQQSfwKSTdAvZbHNhpfK, IpkfHKQ2Sd]:
                result = []
                for foundStringLarge in foundStringsLarge:
                    try:
                        result.append(DecodingFunction(foundStringLarge, foundStringSmall))
                    except:
                        pass

                if ContainsString(result, 'http:'):
                    return result

        foundStringsHex = [foundString for foundString in foundStrings if IsHex(foundString)]
        foundStringsNotHex = [foundString for foundString in foundStrings if not IsHex(foundString)]
        for foundStringNotHex in foundStringsNotHex:
            for DecodingFunction in [KALLKKKASKAJJAS]:
                result = []
                for foundStringHex in foundStringsHex:
                    try:
                        result.append(DecodingFunction(foundStringNotHex, foundStringHex))
                    except:
                        pass

                if ContainsString(result, 'http'):
                    return result

        for foundStringHex1 in foundStringsHex:
            for DecodingFunction in [KALLKKKASKAJJAS]:
                result = []
                for foundStringHex2 in foundStringsHex:
                    try:
                        result.append(DecodingFunction(foundStringHex1, foundStringHex2))
                    except:
                        pass

                if ContainsString(result, 'http'):
                    return result

        return []

AddPlugin(cDridexDecoder)
