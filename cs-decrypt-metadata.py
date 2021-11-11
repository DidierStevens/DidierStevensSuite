#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Cobalt Strike: RSA decrypt metadata'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2021/11/10'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/10/10: start
  2021/10/20: refactoring
  2021/10/26: 0.0.2 parsing binary IPv4 address
  2021/11/10: error handling decrypting; added option -t

Todo:
  
"""

import binascii
import struct
import hashlib
import re
import optparse
import os
import sys
import json
import textwrap
import base64
try:
    import Crypto.PublicKey.RSA
    import Crypto.Cipher.PKCS1_v1_5
except ImportError:
    print('pycrypto module is required: pip install pycryptodome')
    exit(-1)
try:
    import javaobj
except ImportError:
    javaobj = None

def PrintManual():
    manual = r'''
Manual:

This tool decrypts metadata sent by a Cobalt Strike beacon to its team server.
Provide the metadata in base64 format as argument. More than one argument can be provided.
Decrypting metadata requires a private key.
A private key can be provided with option -p in hexadecimal format or with option -f as a file (.cobaltstrike.beacon_keys).
If no private key is provided, all private keys in file 1768.json are tried.

Example:

cs-decrypt-metadata.py KN9zfIq31DBBdLtF4JUjmrhm0lRKkC/I/zAiJ+Xxjz787h9yh35cRjEnXJAwQcWP4chXobXT/E5YrZjgreeGTrORnj//A5iZw2TClEnt++gLMyMHwgjsnvg9czGx6Ekpz0L1uEfkVoo4MpQ0/kJk9myZagRrPrFWdE9U7BwCzlE=

Input: KN9zfIq31DBBdLtF4JUjmrhm0lRKkC/I/zAiJ+Xxjz787h9yh35cRjEnXJAwQcWP4chXobXT/E5YrZjgreeGTrORnj//A5iZw2TClEnt++gLMyMHwgjsnvg9czGx6Ekpz0L1uEfkVoo4MpQ0/kJk9myZagRrPrFWdE9U7BwCzlE=
Encrypted metadata: 28df737c8ab7d4304174bb45e095239ab866d2544a902fc8ff302227e5f18f3efcee1f72877e5c4631275c903041c58fe1c857a1b5d3fc4e58ad98e0ade7864eb3919e3fff039899c364c29449edfbe80b332307c208ec9ef83d7331b1e84929cf42f5b847e4568a38329434fe4264f66c996a046b3eb156744f54ec1c02ce51
Decrypted:
Header: 0000beef
Datasize: 0000005d
Raw key:  caeab4f452fe41182d504aa24966fbd0
 aeskey:  3342f45e6e2f71f5975c998600b11471
 hmackey: 7142dd70f4ec320badac8ca246a9488f
charset: 04e4 ANSI Latin 1; Western European (Windows)
charset_oem: 01b5 OEM United States
bid: 644d8e4 105175268
pid: 1c7c 7292
port: 0
flags: 04
var1: 10
var2: 0
var3: 19042
var4: 0
var5: 1988364896
var6: 1988359504
Internal IPv4: 10.6.9.111
Field: b'DESKTOP-Q21RU7A'
Field: b'maxwell.carter'
Field: b'svchost.exe'

By default, metadata is BASE64 encoded. If another transformation is used by the beacon to encode the metadata, option -t can be used to transform the metadata prior to decrypting.

Example:

cs-decrypt-metadata.py -t 7:Metadata,13,2:__cfduid=,6:Cookie __cfduid=GQ-rUvFDD0WewXldmHhCkZybJ5OB4ZrwbRbN6K4St2Jr7W1L0FR0eSZSdHtt0i9JHBBUzRnQj1U4a0a4meC9YMvgvdSIQ4QlqNEw5GMDKkTYjAcNRRCe3QYZ2FeW4dn5SALu70Eb7F5VzDoFcG_Hq3akmQpHH-RBWPYNxTX2fsE

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def RSAEncrypt(key, data):
    oPublicKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key).rstrip(b'\x00'))
    oRSAPublicKey = Crypto.Cipher.PKCS1_v1_5.new(oPublicKey)
    ciphertext = oRSAPublicKey.encrypt(data)
    ciphertextBASE64 = binascii.b2a_base64(ciphertext).rstrip(b'\n')
    return ciphertextBASE64

def RSADecrypt(key, data):
    oPrivateKey = Crypto.PublicKey.RSA.importKey(binascii.a2b_hex(key))
    oRSAPrivateKey = Crypto.Cipher.PKCS1_v1_5.new(oPrivateKey)
#    ciphertext = binascii.a2b_base64(data)
    ciphertext = data
    try:
        cleartext = oRSAPrivateKey.decrypt(ciphertext, None)
    except ValueError:
        return None
    return cleartext

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def Unpack(self, format):
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        return struct.unpack(format, tounpack)

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None, peek=False):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        if not peek:
            self.data = self.data[length:]
        return result

#https://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx
dCodepages = {
    37: 'IBM EBCDIC US-Canada',
    437: 'OEM United States',
    500: 'IBM EBCDIC International',
    708: 'Arabic (ASMO 708)',
    709: 'Arabic (ASMO-449+, BCON V4)',
    710: 'Arabic - Transparent Arabic',
    720: 'Arabic (Transparent ASMO); Arabic (DOS)',
    737: 'OEM Greek (formerly 437G); Greek (DOS)',
    775: 'OEM Baltic; Baltic (DOS)',
    850: 'OEM Multilingual Latin 1; Western European (DOS)',
    852: 'OEM Latin 2; Central European (DOS)',
    855: 'OEM Cyrillic (primarily Russian)',
    857: 'OEM Turkish; Turkish (DOS)',
    858: 'OEM Multilingual Latin 1 + Euro symbol',
    860: 'OEM Portuguese; Portuguese (DOS)',
    861: 'OEM Icelandic; Icelandic (DOS)',
    862: 'OEM Hebrew; Hebrew (DOS)',
    863: 'OEM French Canadian; French Canadian (DOS)',
    864: 'OEM Arabic; Arabic (864)',
    865: 'OEM Nordic; Nordic (DOS)',
    866: 'OEM Russian; Cyrillic (DOS)',
    869: 'OEM Modern Greek; Greek, Modern (DOS)',
    870: 'IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2',
    874: 'ANSI/OEM Thai (ISO 8859-11); Thai (Windows)',
    875: 'IBM EBCDIC Greek Modern',
    932: 'ANSI/OEM Japanese; Japanese (Shift-JIS)',
    936: 'ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)',
    949: 'ANSI/OEM Korean (Unified Hangul Code)',
    950: 'ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)',
    1026: 'IBM EBCDIC Turkish (Latin 5)',
    1047: 'IBM EBCDIC Latin 1/Open System',
    1140: 'IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro)',
    1141: 'IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro)',
    1142: 'IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro)',
    1143: 'IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro)',
    1144: 'IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro)',
    1145: 'IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro)',
    1146: 'IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro)',
    1147: 'IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro)',
    1148: 'IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro)',
    1149: 'IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro)',
    1200: 'Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications',
    1201: 'Unicode UTF-16, big endian byte order; available only to managed applications',
    1250: 'ANSI Central European; Central European (Windows)',
    1251: 'ANSI Cyrillic; Cyrillic (Windows)',
    1252: 'ANSI Latin 1; Western European (Windows)',
    1253: 'ANSI Greek; Greek (Windows)',
    1254: 'ANSI Turkish; Turkish (Windows)',
    1255: 'ANSI Hebrew; Hebrew (Windows)',
    1256: 'ANSI Arabic; Arabic (Windows)',
    1257: 'ANSI Baltic; Baltic (Windows)',
    1258: 'ANSI/OEM Vietnamese; Vietnamese (Windows)',
    1361: 'Korean (Johab)',
    10000: 'MAC Roman; Western European (Mac)',
    10001: 'Japanese (Mac)',
    10002: 'MAC Traditional Chinese (Big5); Chinese Traditional (Mac)',
    10003: 'Korean (Mac)',
    10004: 'Arabic (Mac)',
    10005: 'Hebrew (Mac)',
    10006: 'Greek (Mac)',
    10007: 'Cyrillic (Mac)',
    10008: 'MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)',
    10010: 'Romanian (Mac)',
    10017: 'Ukrainian (Mac)',
    10021: 'Thai (Mac)',
    10029: 'MAC Latin 2; Central European (Mac)',
    10079: 'Icelandic (Mac)',
    10081: 'Turkish (Mac)',
    10082: 'Croatian (Mac)',
    12000: 'Unicode UTF-32, little endian byte order; available only to managed applications',
    12001: 'Unicode UTF-32, big endian byte order; available only to managed applications',
    20000: 'CNS Taiwan; Chinese Traditional (CNS)',
    20001: 'TCA Taiwan',
    20002: 'Eten Taiwan; Chinese Traditional (Eten)',
    20003: 'IBM5550 Taiwan',
    20004: 'TeleText Taiwan',
    20005: 'Wang Taiwan',
    20105: 'IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5)',
    20106: 'IA5 German (7-bit)',
    20107: 'IA5 Swedish (7-bit)',
    20108: 'IA5 Norwegian (7-bit)',
    20127: 'US-ASCII (7-bit)',
    20261: 'T.61',
    20269: 'ISO 6937 Non-Spacing Accent',
    20273: 'IBM EBCDIC Germany',
    20277: 'IBM EBCDIC Denmark-Norway',
    20278: 'IBM EBCDIC Finland-Sweden',
    20280: 'IBM EBCDIC Italy',
    20284: 'IBM EBCDIC Latin America-Spain',
    20285: 'IBM EBCDIC United Kingdom',
    20290: 'IBM EBCDIC Japanese Katakana Extended',
    20297: 'IBM EBCDIC France',
    20420: 'IBM EBCDIC Arabic',
    20423: 'IBM EBCDIC Greek',
    20424: 'IBM EBCDIC Hebrew',
    20833: 'IBM EBCDIC Korean Extended',
    20838: 'IBM EBCDIC Thai',
    20866: 'Russian (KOI8-R); Cyrillic (KOI8-R)',
    20871: 'IBM EBCDIC Icelandic',
    20880: 'IBM EBCDIC Cyrillic Russian',
    20905: 'IBM EBCDIC Turkish',
    20924: 'IBM EBCDIC Latin 1/Open System (1047 + Euro symbol)',
    20932: 'Japanese (JIS 0208-1990 and 0212-1990)',
    20936: 'Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)',
    20949: 'Korean Wansung',
    21025: 'IBM EBCDIC Cyrillic Serbian-Bulgarian',
    21027: '(deprecated)',
    21866: 'Ukrainian (KOI8-U); Cyrillic (KOI8-U)',
    28591: 'ISO 8859-1 Latin 1; Western European (ISO)',
    28592: 'ISO 8859-2 Central European; Central European (ISO)',
    28593: 'ISO 8859-3 Latin 3',
    28594: 'ISO 8859-4 Baltic',
    28595: 'ISO 8859-5 Cyrillic',
    28596: 'ISO 8859-6 Arabic',
    28597: 'ISO 8859-7 Greek',
    28598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Visual)',
    28599: 'ISO 8859-9 Turkish',
    28603: 'ISO 8859-13 Estonian',
    28605: 'ISO 8859-15 Latin 9',
    29001: 'Europa 3',
    38598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Logical)',
    50220: 'ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS)',
    50221: 'ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana)',
    50222: 'ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI)',
    50225: 'ISO 2022 Korean',
    50227: 'ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)',
    50229: 'ISO 2022 Traditional Chinese',
    50930: 'EBCDIC Japanese (Katakana) Extended',
    50931: 'EBCDIC US-Canada and Japanese',
    50933: 'EBCDIC Korean Extended and Korean',
    50935: 'EBCDIC Simplified Chinese Extended and Simplified Chinese',
    50936: 'EBCDIC Simplified Chinese',
    50937: 'EBCDIC US-Canada and Traditional Chinese',
    50939: 'EBCDIC Japanese (Latin) Extended and Japanese',
    51932: 'EUC Japanese',
    51936: 'EUC Simplified Chinese; Chinese Simplified (EUC)',
    51949: 'EUC Korean',
    51950: 'EUC Traditional Chinese',
    52936: 'HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)',
    54936: 'Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)',
    57002: 'ISCII Devanagari',
    57003: 'ISCII Bengali',
    57004: 'ISCII Tamil',
    57005: 'ISCII Telugu',
    57006: 'ISCII Assamese',
    57007: 'ISCII Oriya',
    57008: 'ISCII Kannada',
    57009: 'ISCII Malayalam',
    57010: 'ISCII Gujarati',
    57011: 'ISCII Punjabi',
    65000: 'Unicode (UTF-7)',
    65001: 'Unicode (UTF-8)'
}

def DecodeMetadata(decrypted):
    oStruct = cStruct(decrypted)
    beef = oStruct.Unpack('>I')[0]
    print('Decrypted:')
    print('Header: %08x' % beef)
    datasize = oStruct.Unpack('>I')[0]
    print('Datasize: %08x' % datasize)
    oStruct.Truncate(datasize)
    rawkey = oStruct.GetBytes(16)
    print('Raw key:  %s' % binascii.b2a_hex(rawkey).decode())
    sha256hex = hashlib.sha256(rawkey).hexdigest()
    aeskey = sha256hex[:32]
    hmackey = sha256hex[32:]
    print(' aeskey:  %s' % aeskey)
    print(' hmackey: %s' % hmackey)
    charset, charset_oem = oStruct.Unpack('<HH')
    print('charset: %04x %s' % (charset, dCodepages.get(charset, '')))
    print('charset_oem: %04x %s' % (charset_oem, dCodepages.get(charset_oem, '')))

    peek = oStruct.GetBytes(peek=True)
    if not re.match(b'[0-9]+\t[0-9]+\t[0-9]', peek):
        bid, pid, port, flags = oStruct.Unpack('>IIHB')
        print('bid: %04x %d' % (bid, bid))
        print('pid: %04x %d' % (pid, pid))
        print('port: %d' % port)
        print('flags: %02x' % flags)

        peek = oStruct.GetBytes(peek=True)
        if not re.match(b'[0-9]+\t[0-9]+\.[0-9]+', peek):
            var1, var2, var3, var4, var5, var6 = oStruct.Unpack('>BBHIII')
            print('var1: %d' % var1)
            print('var2: %d' % var2)
            print('var3: %d' % var3)
            print('var4: %d' % var4)
            print('var5: %d' % var5)
            print('var6: %d' % var6)
            ipv4 = oStruct.GetBytes(4)
            print('Internal IPv4: %s' % '.'.join([str(byte) for byte in ipv4[::-1]]))

    remainder = oStruct.GetBytes()
    for field in remainder.split(b'\t'):
        print('Field: %s' % field)
    print('')

def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])

def GetJSONData():
    filename = os.path.join(GetScriptPath(), '1768.json')
    if not os.path.isfile(filename):
        return {}
    return json.load(open(filename, 'r'))

def BASE64URLDecode(data):
    paddingLength = 4 - len(data) % 4
    if paddingLength <= 2:
        data += b'=' * paddingLength
    return base64.b64decode(data, b'-_')

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None
    
def GetInstructions(instructions, instructionType):
    for result in instructions.split(';'):
        match, remainder = StartsWithGetRemainder(result, '7:%s,' % instructionType)
        if match:
            if instructionType in ['Output', 'Metadata']:
                return ','.join(remainder.split(',')[::-1])
            else:
                return remainder
    return ''

def ProcessInstructions(instructions, rawdata, instructionType):
    instructions = GetInstructions(instructions, instructionType)
    if instructions == '':
        instructions = []
    else:
        instructions = [instruction for instruction in instructions.split(',')]
    data = rawdata
    for instruction in instructions:
        instruction = instruction.split(':')
        opcode = int(instruction[0])
        operands = instruction[1:]
        if opcode == 1:
            if instructionType == 'Metadata':
                data = data[:-len(operands[0])]
            else:
                data = data[:-int(operands[0])]
        elif opcode == 2:
            if instructionType == 'Metadata':
                data = data[len(operands[0]):]
            else:
                data = data[int(operands[0]):]
        elif opcode == 3:
            data = binascii.a2b_base64(data)
        elif opcode == 4:
            pass
        elif opcode == 6:
            pass
        elif opcode == 7:
            pass
        elif opcode == 13:
            data = BASE64URLDecode(data)
        elif opcode == 15:
            xorkey = data[0:4]
            ciphertext = data[4:]
            data = []
            for iter, value in enumerate(ciphertext):
                data.append(value ^ xorkey[iter % 4])
            data = bytes(data)
    return data
            
def DecryptMetadata(arg, options):
    print('Input: %s' % arg)
    arg = ProcessInstructions(options.transform, arg.encode(), 'Metadata')
    print('Encrypted metadata: %s' % binascii.b2a_hex(arg).decode())

    if options.private != '':
        decrypted = RSADecrypt(options.private, arg)
        if decrypted != None:
            DecodeMetadata(decrypted)
    elif options.file != '':
        if javaobj == None:
            print('javaobj module required: pip install javaobj-py3')
            exit(-1)
        pobj = javaobj.load(open(options.file, 'rb'))
        privateKey = binascii.b2a_hex(bytes([number & 0xFF for number in pobj.array.value.privateKey.encoded._data])).decode()
        decrypted = RSADecrypt(privateKey, arg)
        if decrypted != None:
            DecodeMetadata(decrypted)
    else:
        jsonData = GetJSONData()
        for publicKey, dPrivatekey in jsonData['dLookupValues']['7'].items():
            privateKey = dPrivatekey['verbose']
            decrypted = RSADecrypt(privateKey, arg)
            if decrypted != None:
                DecodeMetadata(decrypted)
                break

def Main():
    moredesc = '''
Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] encrypted_metadata\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-p', '--private', default='', help='Private key (hexadecimal)')
    oParser.add_option('-f', '--file', default='', help='File with private key')
    oParser.add_option('-t', '--transform', type=str, default='7:Metadata,3', help='Transformation instructions')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
        return

    for arg in args:
        DecryptMetadata(arg, options)

if __name__ == '__main__':
    Main()
