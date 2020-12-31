#!/usr/bin/env python

__description__ = 'Analyze RTF files'
__author__ = 'Didier Stevens'
__version__ = '0.0.10'
__date__ = '2020/12/23'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/09/01: start
  2015/09/02: continue
  2015/09/09: added --cut ...l and bytes appended after last group
  2015/09/11: added re.I for hex regexes
  2015/09/12: CutData refactoring
  2015/09/14: added YARA support
  2015/09/15: added basic HEX deobfuscation (options -F and -S)
  2015/11/18: added support for -c :-number
  2016/01/23: added support to ExtractHex for obfuscated hex code; updated CutData
  2016/01/23: added option -i
  2016/07/23: 0.0.2 continue; sample 1B8113DC81489FF37202A1E038A7781D
  2016/07/24: continue
  2016/07/26: continue
  2016/07/27: continue
  2016/07/30: 0.0.3 added option recursionlimit
  2016/08/09: 0.0.4 refactoring
  2016/08/12: continue
  2017/02/11: 0.0.5 added \dde000... handling; added option -E
  2017/12/09: 0.0.6 added longestContiguousHexstring; extra info -f O
  2017/12/10: cDump & YARACompile
  2017/12/24: 0.0.7 made changes level 0 -> remainder
  2018/12/07: 0.0.8 added support for -s a; added selection warning; added option -A; added yara #x# #r#; updated ParseCutTerm; added --jsonoutput
  2018/12/09: 0.0.9 changed extra output for remainder
  2019/03/13: 0.0.10 bug fixes
  2019/03/15: continue; package; filter h>int
  2019/10/09: bug fix
  2019/10/27: introduced environment variable DSS_DEFAULT_HASH_ALGORITHMS
  2020/12/06: Python 3, option -n
  2020/12/07: Bug fixes, special characters, removed option -n; added options -v -T; cutdata update
  2020/12/08: added option -I
  2020/12/23: added option -O

Todo:
"""

import optparse
import sys
import os
import zipfile
import binascii
import textwrap
import re
import string
import hashlib
import json
import zlib
import struct
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
if sys.version_info[0] >= 3:
    from io import BytesIO as BytesIO
else:
    from cStringIO import StringIO as BytesIO

try:
    import yara
except:
    pass

dumplinelength = 16
MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

This manual is a work in progress.

By default, this tool uses the MD5 hash in reports, but this can be changed by setting environment variable DSS_DEFAULT_HASH_ALGORITHMS.
Like this: set DSS_DEFAULT_HASH_ALGORITHMS=SHA256

With option -T (--headtail), output can be truncated to the first 10 lines and last 10 lines of output.

With option -j, oledump will output the content of the ole file as a JSON object that can be piped into other tools that support this JSON format.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

#-BEGINCODE cDump------------------------------------------------------------------------------------
#import binascii
#import sys
#if sys.version_info[0] >= 3:
#    from io import StringIO
#else:
#    from cStringIO import StringIO

class cDump():
    def __init__(self, data, prefix='', offset=0, dumplinelength=16):
        self.data = data
        self.prefix = prefix
        self.offset = offset
        self.dumplinelength = dumplinelength

    def HexDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        for i, b in enumerate(self.data):
            if i % self.dumplinelength == 0 and hexDump != '':
                oDumpStream.Addline(hexDump)
                hexDump = ''
            hexDump += IFF(hexDump == '', '', ' ') + '%02X' % self.C2IIP2(b)
        oDumpStream.Addline(hexDump)
        return oDumpStream.Content()

    def CombineHexAscii(self, hexDump, asciiDump):
        if hexDump == '':
            return ''
        countSpaces = 3 * (self.dumplinelength - len(asciiDump))
        if len(asciiDump) <= self.dumplinelength / 2:
            countSpaces += 1
        return hexDump + '  ' + (' ' * countSpaces) + asciiDump

    def HexAsciiDump(self, rle=False):
        oDumpStream = self.cDumpStream(self.prefix)
        position = ''
        hexDump = ''
        asciiDump = ''
        previousLine = None
        countRLE = 0
        for i, b in enumerate(self.data):
            b = self.C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    line = self.CombineHexAscii(hexDump, asciiDump)
                    if not rle or line != previousLine:
                        if countRLE > 0:
                            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
                        oDumpStream.Addline(position + line)
                        countRLE = 0
                    else:
                        countRLE += 1
                    previousLine = line
                position = '%08X:' % (i + self.offset)
                hexDump = ''
                asciiDump = ''
            if i % self.dumplinelength == self.dumplinelength / 2:
                hexDump += ' '
            hexDump += ' %02X' % b
            asciiDump += IFF(b >= 32 and b < 127, chr(b), '.')
        if countRLE > 0:
            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
        oDumpStream.Addline(self.CombineHexAscii(position + hexDump, asciiDump))
        return oDumpStream.Content()

    def Base64Dump(self, nowhitespace=False):
        encoded = binascii.b2a_base64(self.data).decode().strip()
        if nowhitespace:
            return encoded
        oDumpStream = self.cDumpStream(self.prefix)
        length = 64
        for i in range(0, len(encoded), length):
            oDumpStream.Addline(encoded[0+i:length+i])
        return oDumpStream.Content()

    class cDumpStream():
        def __init__(self, prefix=''):
            self.oStringIO = StringIO()
            self.prefix = prefix

        def Addline(self, line):
            if line != '':
                self.oStringIO.write(self.prefix + line + '\n')

        def Content(self):
            return self.oStringIO.getvalue()

    @staticmethod
    def C2IIP2(data):
        if sys.version_info[0] > 2:
            return data
        else:
            return ord(data)

def HexDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump(rle=rle)

def RemoveLeadingEmptyLines(data):
    if data[0] == '':
        return RemoveLeadingEmptyLines(data[1:])
    else:
        return data

def RemoveTrailingEmptyLines(data):
    if data[-1] == '':
        return RemoveTrailingEmptyLines(data[:-1])
    else:
        return data

def HeadTail(data, apply):
    count = 10
    if apply:
        lines = RemoveTrailingEmptyLines(RemoveLeadingEmptyLines(data.split('\n')))
        if len(lines) <= count * 2:
            return data
        else:
            return '\n'.join(lines[0:count] + ['...'] + lines[-count:])
    else:
        return data

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        if isinstance(data, str):
            sys.stdout.write(data)
        else:
            sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cIteminfo():
    def __init__(self, level, beginPosition, endPosition, countChildren):
        self.level = level
        self.beginPosition = beginPosition
        self.endPosition = endPosition
        self.countChildren = countChildren

def BuildTree(rtfdata, level, index, sequence, options):
    children = 0
    level += 1
    if index >= len(rtfdata):
        return None
    if rtfdata[index:index+1] != b'{':
        error = 'Parser error: Expected character {'
        print(error)
        raise Exception(error)
    start = index
    oIteminfo = cIteminfo(level, start, None, None)
    sequence.append(oIteminfo)
    index += 1
    while index < len(rtfdata):
        if rtfdata[index:index+1] == b'{' and (index == 0 or rtfdata[index - 1:index] != b'\\'):
            index = BuildTree(rtfdata, level, index, sequence, options)
            children += 1
        elif rtfdata[index:index+1] == b'}' and (index == 0 or rtfdata[index - 1:index] != b'\\'):
            oIteminfo.endPosition = index
            oIteminfo.countChildren = children
            return index + 1
        else:
            index += 1
    if options.select == '':
        print('Parser warning: Missing terminating character } level = %d' % level)
    oIteminfo.endPosition = index
    oIteminfo.countChildren = children
    return index

def Trimdde(data):
    if not data.startswith(b'\r\n\\dde'):
        return data
    data = data[6:]
    counter = 0
    while data[counter] == b'0' and counter < 250:
        counter += 1
    return data[counter:]

def ExtractHex(data, controlwordsToIgnore):
    # special characters http://latex2rtf.sourceforge.net/rtfspec_7.html#rtfspec_specialchar
    # sample 5c3d12b29a1bb9fb775bb6d862a32ae8e89af943b6337c71fe2268dee70055e9
    control_words_special_characters = [b'\\qmspace']

    data = Trimdde(data)
    if data.startswith(b'\r\n\\dde'):
        print(repr(data[0:40]))
    backslash = False
    backslashtext = b''
    hexstring = [StringIO()]
    countUnexpectedCharacters = 0
    binstatus = 0
    binnumber = b''
    bintext = b''
    specialcharacterStatus = False
    i = 0
    while i < len(data):
        if sys.version_info[0] >= 3:
            byte = bytes([data[i]])
        else:
            byte = data[i]
        if specialcharacterStatus:
            if byte == b'}':
                specialcharacterStatus = False
            else:
                pass
        elif binstatus > 0:
            if binstatus == 1:
                if byte in string.digits.encode():
                    binnumber += byte
                else:
                    binstatus = 2
                    if binnumber == b'':
                        binint = 0
                    else:
                        binint = int(binnumber) & 0xFFFFFFFF
                    bintext = b''
                    if binint == 0:
                        binstatus = 0
                    if not byte in string.whitespace.encode():
                        i -= 1
            elif binstatus == 2:
                    bintext += byte
                    binint -= 1
                    if binint == 0:
                        binstatus = 0
                        hexstring.append(['bin', bintext])
                        hexstring.append(StringIO())
                        binnumber = b''
                        bintext = b''
        elif backslash:
            if byte in string.ascii_letters.encode() or byte in string.digits.encode() or byte == b'-':
                backslashtext += byte
                if backslashtext == b'\\bin':
                    binstatus = 1
                    binnumber = b''
                    backslash = False
                    backslashtext = b''
                if backslashtext in control_words_special_characters + controlwordsToIgnore:
                    specialcharacterStatus = True
            elif backslashtext == b'\\':
                backslash = False
                backslashtext = b''
            else:
#                if backslashtext != '\\-':
#                    print(repr(backslashtext))
                backslash = False
                backslashtext = b''
                i -= 1
        elif byte == b'\\':
            backslash = True
            backslashtext = byte
        elif byte in string.hexdigits.encode():
            hexstring[-1].write(byte.decode())
        elif byte in string.whitespace.encode():
            pass
        elif byte == b'{':
            pass
        elif byte == b'}':
            pass
        else:
            countUnexpectedCharacters += 1
#            print(hexstring)
#            print(repr(char))
#            if not char in ['\0']:
#                raise('xxx')
        i += 1
    return [IFF(isinstance(x, list), x, lambda: x.getvalue()) for x in hexstring], max([b''] + re.findall(b'[0-9a-f]+', data, re.I), key=len), countUnexpectedCharacters

def ReadWORD(data):
    format = '<H'
    length = struct.calcsize(format)
    if len(data) < length:
        return None, None
    return struct.unpack(format, data[:length])[0], data[length:]

def ReadDWORD(data):
    format = '<I'
    length = struct.calcsize(format)
    if len(data) < length:
        return None, None
    return struct.unpack(format, data[:length])[0], data[length:]

def ReadDWORDString(data):
    dword1, data = ReadDWORD(data)
    if dword1 == None:
        return None, None
    if dword1 == 0:
        return b'', data
    return data[:dword1], data[dword1:]

def ReadNullTerminatedString(data):
    position = data.find(b'\x00')
    if position == -1:
        return None, None
    return data[:position], data[position + 1:]

class cHashCRC32():
    def __init__(self):
        self.crc32 = None

    def update(self, data):
        self.crc32 = zlib.crc32(data)

    def hexdigest(self):
        return '%08x' % (self.crc32 & 0xffffffff)

def GetHashObjects(algorithms):
    dHashes = {}

    if algorithms == '':
        algorithms = os.getenv('DSS_DEFAULT_HASH_ALGORITHMS', 'md5')
    if ',' in algorithms:
        hashes = algorithms.split(',')
    else:
        hashes = algorithms.split(';')
    for name in hashes:
        if name != 'crc32' and not name in hashlib.algorithms_available:
            print('Error: unknown hash algorithm: %s' % name)
            print('Available hash algorithms: ' + ' '.join(name for name in list(hashlib.algorithms_available) + ['crc32']))
            return [], {}
        elif name == 'crc32':
            dHashes[name] = cHashCRC32()
        else:
            dHashes[name] = hashlib.new(name)

    return hashes, dHashes

def CalculateChosenHash(data):
    hashes, dHashes = GetHashObjects('')
    dHashes[hashes[0]].update(data)
    return dHashes[hashes[0]].hexdigest(), hashes[0]

def ExtractPackage00(data):
    dataLen = len(data)
    word1, data = ReadWORD(data)
    if word1 == None:
        return []
    name, data = ReadNullTerminatedString(data)
    if name == None:
        return []
    pathname1, data = ReadNullTerminatedString(data)
    if pathname1 == None:
        return []
    dword2, data = ReadDWORD(data)
    if dword2 == None:
        return []
    dword3, data = ReadDWORD(data)
    if dword3 == None:
        return []
    pathname2, data = ReadNullTerminatedString(data)
    if pathname2 == None:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []
    content = data[:sizeEmbedded]
    return [name, pathname1, pathname2, dataLen - len(data), sizeEmbedded, content]

# https://msdn.microsoft.com/en-us/library/dd942076.aspx
# https://www.linkedin.com/pulse/microsoft-office-zero-day-detecting-hta-handler-kevin-douglas
def ExtractOleInfo(data):
    dataSave = data
    dword1, data = ReadDWORD(data)
    if dword1 == None:
        return []
    dword2, data = ReadDWORD(data)
    if dword2 == None or dword2 != 0x00000001 and dword2 != 0x00000002:
        return []
    classname, data = ReadDWORDString(data)
    if classname == None:
        return []
    topicname, data = ReadDWORDString(data)
    if topicname == None:
        return []
    itemname, data = ReadDWORDString(data)
    if itemname == None:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []

    position = len(dataSave) - len(data)
    content = dataSave[position:position + sizeEmbedded]

    if classname == b'Package\x00':
        result = ExtractPackage00(content)
        if result != []:
            classname = classname + b':' + result[0]
            position = position + result[3]
            sizeEmbedded = result[4]
            content = result[5]

    return [classname, position, sizeEmbedded, CalculateChosenHash(content), binascii.b2a_hex(content[:4]), content]

def Info(data):
    result = ExtractOleInfo(data)
    if result == []:
        return 'Error: extraction failed'
    return 'Name: %s\nPosition embedded: %08x\nSize embedded: %08x\n%s: %s\nmagic: %s\n' % (repr(result[0]), result[1], result[2], result[3][1], result[3][0], result[4])

def ExtractPackage(data):
    result = ExtractOleInfo(data)
    return data[result[1]:result[1] + result[2]]

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

def ParseInteger(argument):
    sign = 1
    if argument.startswith('+'):
        argument = argument[1:]
    elif argument.startswith('-'):
        argument = argument[1:]
        sign = -1
    if argument.startswith('0x'):
        return sign * int(argument[2:], 16)
    else:
        return sign * int(argument)

def ParseCutTerm(argument):
    if argument == '':
        return CUTTERM_NOTHING, None, ''
    oMatch = re.match(r'\-?0x([0-9a-f]+)', argument, re.I)
    if oMatch == None:
        oMatch = re.match(r'\-?(\d+)', argument)
    else:
        value = int(oMatch.group(1), 16)
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[u?\'(.+?)\'\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        if argument.startswith("[u'"):
            # convert ascii to unicode 16 byte sequence
            searchtext = oMatch.group(1).decode('unicode_escape').encode('utf16')[2:]
        else:
            searchtext = oMatch.group(1)
        return CUTTERM_FIND, (searchtext, int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

def ParseCutArgument(argument):
    type, value, remainder = ParseCutTerm(argument.strip())
    if type == CUTTERM_NOTHING:
        return CUTTERM_NOTHING, None, CUTTERM_NOTHING, None
    elif type == None:
        if remainder.startswith(':'):
            typeLeft = CUTTERM_NOTHING
            valueLeft = None
            remainder = remainder[1:]
        else:
            return None, None, None, None
    else:
        typeLeft = type
        valueLeft = value
        if typeLeft == CUTTERM_POSITION and valueLeft < 0:
            return None, None, None, None
        if typeLeft == CUTTERM_FIND and valueLeft[1] == 0:
            return None, None, None, None
        if remainder.startswith(':'):
            remainder = remainder[1:]
        else:
            return None, None, None, None
    type, value, remainder = ParseCutTerm(remainder)
    if type == CUTTERM_POSITION and remainder == 'l':
        return typeLeft, valueLeft, CUTTERM_LENGTH, value
    elif type == None or remainder != '':
        return None, None, None, None
    elif type == CUTTERM_FIND and value[1] == 0:
        return None, None, None, None
    else:
        return typeLeft, valueLeft, type, value

def Find(data, value, nth, startposition=-1):
    position = startposition
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return [stream, None, None]

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return [stream, None, None]

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ['', None, None]
        positionBegin += valueLeft[2]
    else:
        raise Exception("Unknown value typeLeft")

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1], positionBegin)
        if positionEnd == -1:
            return ['', None, None]
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return [stream[positionBegin:positionEnd], positionBegin, positionEnd]

def HexDecode(hexstream, options):
    if hexstream == None:
        return b''
    result = b''
    for entry in hexstream:
        if isinstance(entry, str):
            if len(entry) % 2 == 1:
                if options.hexshift:
                    hexdata = '0' + entry
                else:
                    hexdata = entry + '0'
            elif options.hexshift:
                hexdata = '0' + entry + '0'
            else:
                hexdata = entry
            result += binascii.a2b_hex(hexdata)
        else:
            result += entry[1]
    return result

def HexDecodeIfRequested(info, options):
    if options.hexdecode:
        hexstream = info.hexstring
        if hexstream == None:
            return info.content
        return HexDecode(hexstream, options)
    else:
        return info.content

def HexBinCount(hexstream):
    hexcount = 0
    bincount = 0
    for entry in hexstream:
        if isinstance(entry, str):
            hexcount += len(entry)
        else:
            bincount += len(entry[1])
    return hexcount, bincount

class cAnalysis():
    def __init__(self, index, leader, level, beginPosition, endPosition, countChildren, countUnexpectedCharacters, controlWord, content, hexstring, longestContiguousHexstring, oleInfo):
        self.index = index
        self.leader = leader
        self.level = level
        self.beginPosition = beginPosition
        self.endPosition = endPosition
        self.countChildren = countChildren
        self.countUnexpectedCharacters = countUnexpectedCharacters
        self.controlWord = controlWord
        self.content = content
        self.hexstring = hexstring
        self.longestContiguousHexstring = longestContiguousHexstring
        self.oleInfo = oleInfo

def GenerateMAGIC(data):
    if sys.version_info[0] > 2:
        return binascii.b2a_hex(data).decode() + ' ' + ''.join([IFF(c >= 32 and c < 127, chr(c), '.') for c in data])
    else:
        return binascii.b2a_hex(data) + ' ' + ''.join([IFF(ord(c) >= 32 and c < 127, c, '.') for c in data])

def RTFSub(oBytesIO, prefix, rules, options):
    returnCode = 0

    if options.filter != '':
        options.filter = options.filter.replace(' ', '')
        if options.filter == 'O':
            options.filter = ['O']
        elif options.filter == 'h':
            options.filter = ['h', 0]
        elif options.filter.startswith('h>'):
            options.filter = ['h', int(options.filter[2:])]
        else:
            print('Unknown filter: %s' % options.filter)
            return returnCode

    sys.setrecursionlimit(options.recursionlimit)

    if options.ignore != '':
        controlwordsToIgnore = options.ignore.encode().split(b',')
    else:
        controlwordsToIgnore = []

    counter = 1
    rtfdata = oBytesIO.read()
    if not rtfdata.startswith(b'{'):
        print('This file does not start with an opening brace: {\nCheck if it is an RTF file.\nMAGIC: %s' % GenerateMAGIC(rtfdata[0:4]))
        return -1
    sequence = []
    BuildTree(rtfdata, 0, 0, sequence, options)
    remainder = rtfdata[sequence[0].endPosition + 1:]
    if len(remainder) > 0:
        sequence.append(cIteminfo(0, sequence[0].endPosition + 1, len(rtfdata) - 1, 0))
    dAnalysis = {}
    for oIteminfo in sequence:
        controlWord = b''
        if oIteminfo.level != 0:
            oMatch = re.match(r'(\\\*)?\\[a-z]+(-?[0-9]+)? ?'.encode(), rtfdata[oIteminfo.beginPosition + 1:])
            if oMatch != None:
                controlWord = oMatch.group(0)
            beginContent = oIteminfo.beginPosition + 1 + len(controlWord)
            endContent = oIteminfo.endPosition - 1
            if beginContent < endContent:
                content = rtfdata[beginContent:endContent + 1]
            else:
                content = b''
        else:
            content = rtfdata[oIteminfo.beginPosition:]
        hexstring, longestContiguousHexstring, countUnexpectedCharacters = ExtractHex(content, controlwordsToIgnore)
        if oIteminfo.level == 0:
            leader = 'Remainder      '
        else:
            leader = '%sLevel %2d                      ' % (' ' * (oIteminfo.level - 1), oIteminfo.level)
        dAnalysis[counter] = cAnalysis(counter, leader, oIteminfo.level, oIteminfo.beginPosition, oIteminfo.endPosition + IFF(oIteminfo.level == 0, 1, 0), oIteminfo.countChildren, countUnexpectedCharacters, controlWord, content, hexstring, longestContiguousHexstring, ExtractOleInfo(HexDecode(hexstring, options)))
        counter += 1

    if options.jsonoutput:
        object = []
        for counter in range(1, len(dAnalysis) + 1):
            data = HexDecodeIfRequested(dAnalysis[counter], options)
            if options.extract and len(data) > 0:
                try:
                    data = ExtractPackage(data)
                except:
                    data = b''
            object.append({'id': counter, 'name': str(counter), 'content': binascii.b2a_base64(data).decode().strip('\n')})
        print(json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': object}))
        return

    if options.objects:
        dObjects = {}
        dHashes = {}
        counter = 1
        for analysis in dAnalysis.values():
            if analysis.oleInfo != []:
                if not analysis.oleInfo[3][0] in dHashes:
                    dHashes[analysis.oleInfo[3][0]] = counter
                    dObjects[counter] = analysis
                    counter += 1

        if options.select == '':
            for key in sorted(dObjects.keys()):
                oleInfo = dObjects[key].oleInfo
                print('%d: Name: %s' % (key, oleInfo[0]))
                print('   Magic: %s' % oleInfo[4])
                print('   Size: %d' % oleInfo[2])
                print('   Hash: %s %s' % (oleInfo[3][1], oleInfo[3][0]))
        else:
            if options.dump:
                DumpFunction = lambda x:x
                IfWIN32SetBinary(sys.stdout)
            elif options.hexdump:
                DumpFunction = HexDump
            elif options.info:
                DumpFunction = Info
            elif options.asciidumprle:
                DumpFunction = lambda x: HexAsciiDump(x, True)
            else:
                DumpFunction = HexAsciiDump
            if options.extract:
                ExtractFunction = ExtractPackage
            else:
                ExtractFunction = lambda x:x

            keys = list(dObjects.keys())
            for key in keys:
                if options.select != 'a' and options.select != str(key):
                    del dObjects[key]
            if len(dObjects) == 0:
                print('Warning: no item was selected with expression %s' % options.select)
                return
            for key in sorted(dObjects.keys()):
                StdoutWriteChunked(HeadTail(DumpFunction(CutData(dObjects[key].oleInfo[5], options.cut)[0]), options.headtail))
    else:
        if options.select == '':
            for counter in range(1, len(dAnalysis) + 1):
                hexcount, bincount = HexBinCount(dAnalysis[counter].hexstring)
                if options.filter == '' or options.filter[0] == 'O' and dAnalysis[counter].oleInfo != [] or options.filter[0] == 'h' and hexcount > options.filter[1]:
                    length = dAnalysis[counter].endPosition - dAnalysis[counter].beginPosition - IFF(dAnalysis[counter].level == 0, 0, 1)
                    line = '%5d %s c=%5d p=%08x l=%8d h=%8d;%8d b=%8d %s u=%8d %s' % (counter, dAnalysis[counter].leader[0:15], dAnalysis[counter].countChildren, dAnalysis[counter].beginPosition, length, hexcount, len(dAnalysis[counter].longestContiguousHexstring), bincount, IFF(dAnalysis[counter].oleInfo != [], 'O', ' '), dAnalysis[counter].countUnexpectedCharacters, dAnalysis[counter].controlWord.decode().strip())
                    if dAnalysis[counter].controlWord.strip() == b'\\*\\objclass':
                        line += ' ' + dAnalysis[counter].content.decode()
                    linePrinted = False
                    if options.yara == None:
                        print(line)
                        if dAnalysis[counter].oleInfo != []:
                            print('      Name: %s Size: %d %s: %s magic: %s' % (repr(dAnalysis[counter].oleInfo[0]), dAnalysis[counter].oleInfo[2], dAnalysis[counter].oleInfo[3][1], dAnalysis[counter].oleInfo[3][0], dAnalysis[counter].oleInfo[4].decode()))
                        if dAnalysis[counter].level == 0:
                            message = []
                            countWhitespace = len([c for c in dAnalysis[counter].content if chr(c) in string.whitespace])
                            countNull = dAnalysis[counter].content.count(b'\x00')
                            if countWhitespace == len(dAnalysis[counter].content):
                                message.append('Only whitespace = %d' % countWhitespace)
                            elif countNull == len(dAnalysis[counter].content):
                                message.append('Only NULL bytes = %d' % countNull)
                            elif countWhitespace + countNull == len(dAnalysis[counter].content):
                                message.append('Only whitespace = %d and NULL bytes = %d' % (countWhitespace, countNull))
                            else:
                                if countWhitespace > 0:
                                    message.append('Whitespace = %d' % countWhitespace)
                                if countNull > 0:
                                    message.append('NULL bytes = %d' % countNull)
                                if dAnalysis[counter].content.count(b'{') > 0:
                                    message.append('Left curly braces = %d' % dAnalysis[counter].content.count(b'{'))
                                if dAnalysis[counter].content.count(b'}') > 0:
                                    message.append('Right curly braces = %d' % dAnalysis[counter].content.count(b'}'))
                            print('      ' + '  '.join(message))
                        linePrinted = True
                    elif dAnalysis[counter].content != None:
                        stream = HexDecodeIfRequested(dAnalysis[counter], options)
                        for result in rules.match(data=stream):
                            if not linePrinted:
                                print(line)
                                linePrinted = True
                            print('               YARA rule: %s' % result.rule)
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('               %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                    print('                %s' % repr(stringdata[2]))
        else:
            if options.dump:
                DumpFunction = lambda x:x
                IfWIN32SetBinary(sys.stdout)
            elif options.hexdump:
                DumpFunction = HexDump
            elif options.info:
                DumpFunction = Info
            elif options.asciidumprle:
                DumpFunction = lambda x: HexAsciiDump(x, True)
            else:
                DumpFunction = HexAsciiDump
            if options.extract:
                ExtractFunction = ExtractPackage
            else:
                ExtractFunction = lambda x:x

            keys = list(dAnalysis.keys())
            for key in keys:
                if options.select != 'a' and options.select != str(key):
                    del dAnalysis[key]
            if len(dAnalysis) == 0:
                print('Warning: no item was selected with expression %s' % options.select)
                return
            for key in sorted(dAnalysis.keys()):
                StdoutWriteChunked(HeadTail(DumpFunction(ExtractFunction(CutData(HexDecodeIfRequested(dAnalysis[key], options), options.cut)[0])), options.headtail))

    return returnCode

def YARACompile(ruledata):
    if ruledata.startswith('#'):
        if ruledata.startswith('#h#'):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith('#b#'):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith('#s#'):
            rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#q#'):
            rule = ruledata[3:].replace("'", '"')
        elif ruledata.startswith('#x#'):
            rule = 'rule hexadecimal {strings: $a = { %s } condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#r#'):
            rule = 'rule regex {strings: $a = /%s/ ascii wide nocase condition: $a}' % ruledata[3:]
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule, externals={'streamname': '', 'VBA': False}), rule
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths, externals={'streamname': '', 'VBA': False}), ','.join(dFilepaths.values())


def RTFDump(filename, options):
    returnCode = 0

    rules = None
    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return returnCode
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        if sys.version_info[0] > 2:
            oBytesIO = BytesIO(sys.stdin.buffer.read())
        else:
            oBytesIO = BytesIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oBytesIO = BytesIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oBytesIO = BytesIO(open(filename, 'rb').read())

    returnCode = RTFSub(oBytesIO, '', rules, options)

    return returnCode

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-O', '--objects', action='store_true', default=False, help='produce overview of objects')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-T', '--headtail', action='store_true', default=False, help='do head & tail')
    oParser.add_option('-H', '--hexdecode', action='store_true', default=False, help='decode hexadecimal data; append 0 in case of uneven number of hexadecimal digits')
    oParser.add_option('-S', '--hexshift', action='store_true', default=False, help='shift one nibble')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file or directory to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-E', '--extract', action='store_true', default=False, help='extract package')
    oParser.add_option('-f', '--filter', type=str, default='', help='filter')
    oParser.add_option('-I', '--ignore', type=str, default='', help='control words to ignore')
    oParser.add_option('--recursionlimit', type=int, default=2000, help='set recursionlimit for Python (default 2000)')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors and YARA rules')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-c) is invalid: %s' % options.cut)
        return 0

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    elif len(args) == 0:
        return RTFDump('', options)
    else:
        return RTFDump(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
