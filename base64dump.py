#!/usr/bin/env python

__description__ = 'Extract base64 strings from file'
__author__ = 'Didier Stevens'
__version__ = '0.0.19'
__date__ = '2021/12/15'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/06/30: start
  2015/07/01: added header
  2015/07/14: 0.0.2: added option -n
  2015/07/28: fixed option -n
  2015/09/12: 0.0.3: added option -c
  2015/11/18: 0.0.4 added support for -c :-number
  2016/01/22: added option ignorewhitespace
  2016/01/23: updated CutData
  2016/11/08: 0.0.5 added option -e; unique bytes; option -S
  2016/11/18: added hex encoding
  2017/02/12: 0.0.6 added encoding all and option -u
  2017/02/13: updated man
  2017/07/01: 0.0.7 added option -z
  2017/10/21: 0.0.8 added option -t
  2018/05/07: 0.0.9: added bx and ah encoding; added YARA support; added decoders
  2018/05/23: 0.0.10: added zxle and zxbe encoding; added option --ignore
  2018/07/23: 0.0.11: added option -I
  2020/07/02: 0.0.12: added zxc encoding, verbose YARACompile, updated CutData, option -A, selection warning, DSS_DEFAULT_HASH_ALGORITHMS, option --jsonoutput, option -T, option -p
  2020/12/25: 0.0.13 added dec encoding; Translate refactoring
  2021/05/23: 0.0.14 added nb decoding
  2021/07/16: 0.0.15 bug fix -i -I options; man page changes
  2021/07/16: 0.0.16 added b85 decoding
  2021/09/27: 0.0.17 added select L; added a85 decoding
  2021/11/14: 0.0.18 fixed DecodeDataDecimal
  2021/12/15: 0.0.19 Python 3 bugfix

Todo:
  add base64 url
"""

import optparse
import sys
import os
import zipfile
import binascii
import textwrap
import re
import hashlib
import string
import math
import string
import codecs
import zlib
import json
import operator
import base64
try:
    import yara
except:
    pass
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO

dumplinelength = 16
MALWARE_PASSWORD = b'infected'
REGEX_STANDARD = b'[\x09\x20-\x7E]'

global dEncodings

def PrintManual():
    manual = '''
Manual:

base64dump is a program that extracts and decodes base64 strings (or other encodings) found inside the provided file. base64dump looks for sequences of base64 characters (or other encodings) in the provided file and tries to decode them.

Other encodings than base64 can be used via option -e.

The result is displayed in a table like this (base64 encoding example):

ID  Size    Encoded          Decoded          MD5 decoded
--  ----    -------          -------          -----------
 1:  400728 TVqQAAMAAAAEAAAA MZ.............. d611941e0d24cb6b59c7b6b2add4fd8f
 2:      36 U2NyaXB0aW5nLkZp Scripting.FileSy a1c46f599699a442a5ae0454467f6d63
 3:       4 exel             {..              f1b1127ffb842243f9a03e67036d4bb6

The first column (ID) is the number (ID) assigned to the datastream by base64dump. This ID is used when selecting a datastream for further analysis with option -s.
The second column (Size) is the length of the base64 string.
The third column (Encoded) is the start of the base64 string.
The fourth column (Decoded) is the ASCII dump of the start of the decoded base64 string.
The fifth column (MD5 decoded) is the MD5 hash of the decoded base64 string.
By default, it's the MD5 hash, but this can be changed by setting environment variable DSS_DEFAULT_HASH_ALGORITHMS.
Like this: set DSS_DEFAULT_HASH_ALGORITHMS=sha256

By default, base64dump will search for base64 encoding strings. It's possible to specify other encodings by using option -e. This option takes the following values:
''' + '\n'.join(dEncodings.keys()) + '''

b64 stands for BASE64, it looks like this: TVqQAAMAAAAEAAAA...
bu stands for "backslash UNICODE" (\\u), it looks like this: \\u9090\\ueb77...
pu stands for "percent UNICODE" (%u), it looks like this: %u9090%ueb77...
hex stands for "hexadecimal", it looks like this: 6D6573736167652C...
bx stands for "backslash hexadecimal" (\\x), it looks like this: \\x90\\x90...
ah stands for "ampersand hexadecimal" (&H), it looks like this: &H90&H90...
zxle stands for "zero hexadecimal little-endian" (0x), it looks like this: 0x909090900xeb77...
zxbe stands for "zero hexadecimal big-endian" (0x), it looks like this: 0x909090900x77eb...
zxc stands for "zero hexadecimal comma" (0x), it looks like this: 0x90,0x90,0x90,0x90...
dec stands for "decimal", it looks like this: 80;75;3;4...
nb stands for "NETBIOS", it looks like this: ENFKOIAA
b85 stands for BASE85 RFC 1924, it looks like this: X>D+Ca&#bLba`-Pb31o...
a85 stands for ASCII85, it looks like this: BOu!rD]...

zxle and zxbe encoding looks for 1 to 8 hexadecimal characters after the prefix 0x. If the number of hexadecimal characters is uneven, a 0 (digit zero) will be prefixed to have an even number of hexadecimal digits.

Select a datastream for further analysis with option -s followed by the ID number of the datastream, L for the largest one, or a for all. For example -s 2:

Info:
 MD5: d611941e0d24cb6b59c7b6b2add4fd8f
 Filesize: 300544
 Entropy: 6.900531
 Unique bytes: 256 (100.00%)
 Magic HEX: 4d5a9000
 Magic ASCII: MZ..
 Null bytes: 41139
 Control bytes: 38024
 Whitespace bytes: 9369
 Printable bytes: 122967
 High bytes: 89045

This displays information for the datastream, like the entropy of the datastream.

The selected stream can be dumped (-d), hexdumped (-x), ASCII dumped (-a) or dump the strings (-S). Use the dump option (-d) to extract the stream and save it to disk (with file redirection >) or to pipe it (|) into the next command.
If the dump needs to be processed by a string codec, like utf16, use option -t instead of -d and provide the codec:
C:\Demo>base64dump.py -s 1 -t utf16 test.bin
You can also provide a Python string expression, like .decode('utf16').encode('utf8').

Here is an example of an ascii dump (-s 2 -a):

00000000: 53 63 72 69 70 74 69 6E 67 2E 46 69 6C 65 53 79  Scripting.FileSy
00000010: 73 74 65 6D 4F 62 6A 65 63 74                    stemObject

You can also specify the minimum length of the decoded base64 datastream with option -n.

With option -w (ignorewhitespace), you can instruct base64dump to ignore all whitespace characters. So for example if the base64 text is split into lines, then you will get one base64 stream.
With option -z (ignorenullbytes), you can instruct base64dump to ignore all leading 0x00 bytes. This can help to decode UNICODE text.
With option -i (ignore), you can instruct base64dump to ignore all characters you provide as a value to option -i. For example, with -i , you can parse strings like 0x44332211,0x88776655,... with encoding zxle by ignoring the separator character ,.
Option -I is like option -i, except that you specify the characters to ignore as an hexadecimal string. For example, -I 2226 will ignore characters " (22) and & (26).

It's also possible to try all encodings: all
Example:
base64dump.py -e all -n 80 sample.vir

Enc  Size    Encoded          Decoded          MD5 decoded
---  ----    -------          -------          -----------
b64:     176 bebafeca41414141 m.+}t.p^5p^5p^5p e3bed37dcd137c9bb5da103d3c45be49
hex:     176 bebafeca41414141 +..-AAAAAAAAAAAA 56464bd2b2c42bbf2edda87d54ab91f5
b64:     192 28000e1358000e13 .-4-fwt-4-fwm.+} 81c587874b1c3ddc5479a283179d29f7
hex:     192 28000e1358000e13 (...X...+..-AAAA 3a604ca304d1dbbcc1734a430cf6dc82
b64:    2144 6064a1000000008b dN+k]4+M4+O.pM8. 46d100d435a37f89f3ab0ac6db3e9cac
hex:    2144 6064a1000000008b .d......@.%....f a2ae7b55955262ada177862ceb683977
b64:    3640 48895C2408488974 p-=S-+++<=....tp f0384b0c74e9402ab3f1aacc4a270ed3
hex:    3640 48895C2408488974 H.\$.H.t$.H.|$.U 3320b9e508862886d2c3f556cacc67ec
b64:  213024 5555555566666666 tPytPyd..d....Z. c7ff5e1a5a01698f99f67fd3f0d20d6d
hex:  213024 5555555566666666 UUUUffffMZ...... 7a618dc1ef3f52693b8ec22dbe0300ec
b64:  246816 5555555566666666 tPytPyd..d....Z. bdec177dc760d4296aefbbdc4c47bcf2
hex:  246816 5555555566666666 UUUUffffMZ...... a69fa966087f38241544523d437f9a8b

The list is sorted by increasing size.

Identical decoded content can be made unique with option -u.

base64dump can scan the content of the datastreams with YARA rules (the YARA Python module must be installed). You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files. Or you can provide the YARA rule with the option value if it starts with # (literal), #s# (string), #q# (quote), #h# (hexadecimal) or #b# (base64). Example: -y "#rule demo {strings: $a=\"demo\" condition: $a}"
Using #s#demo will instruct base64dump to generate a rule to search for string demo (rule string {strings: $a = "demo" ascii wide nocase condition: $a) and use that rule.
All datastreams are scanned with the provided YARA rules, you can not use option -s to select an individual datastream.

Example:
C:\Demo>base64dump.py -y contains_pe_file.yara malware.zip
Enc  Size    Encoded          Decoded          MD5 decoded
---  ----    -------          -------          -----------
 ah:  256000 &H4d&H5a&H90&H00 MZ.............. 5cd40560a53fda5b32c35adfcdfca3e1
     YARA rule: Contains_PE_File

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) in the decoded data.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
C:\Demo>base64dump.py -y contains_pe_file.yara --yarastrings malware.zip
Enc  Size    Encoded          Decoded          MD5 decoded
---  ----    -------          -------          -----------
 ah:  256000 &H4d&H5a&H90&H00 MZ.............. 5cd40560a53fda5b32c35adfcdfca3e1
     YARA rule: Contains_PE_File
     000000 $a:
      4d5a
      'MZ'

YARA rule contains_pe_file detects PE files by finding string MZ followed by string PE at the correct offset (AddressOfNewExeHeader).
The rule looks like this:
rule Contains_PE_File
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a PE file inside a byte sequence"
        method = "Find string MZ followed by string PE at the correct offset (AddressOfNewExeHeader)"
    strings:
        $a = "MZ"
    condition:
        for any i in (1..#a): (uint32(@a[i] + uint32(@a[i] + 0x3C)) == 0x00004550)
}

When looking for traces of Windows executable code (PE files, shellcode, ...) with YARA rules, one must take into account the fact that the executable code might have been encoded (for example via XOR and a key) to evade detection.
To deal with this possibility, base64dump supports decoders. A decoder is a type of plugin, that will bruteforce a type of encoding on each datastream. For example, decoder_xor1 will encode each datastream via XOR and a key of 1 byte. So effectively, 256 different encodings of the datastream will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
C:\Demo>base64dump.py -y contains_pe_file.yara -D decoder_xor1 malware.zip
Enc  Size    Encoded          Decoded          MD5 decoded
---  ----    -------          -------          -----------
 ah:  256000 &H4d&H5a&H90&H00 MZ.............. 5cd40560a53fda5b32c35adfcdfca3e1
     YARA rule (decoder: XOR 1 byte key 0x14): Contains_PE_File
     000000 $a:
      4d5a
      'MZ'

You can specify decoders in exactly the same way as plugins, for example specifying more than one decoder separated by a comma ,.
If decoders are located in a different directory, you could specify it with the --decoderdir option.
Some decoders take options, to be provided with option --decoderoptions.

Some malformed encodings, like BASE64 strings with a number of digits that is not a multiple of 4, will not be detected by base64dump.py.
Such strings are detected using regular expressions, but are then discarded because they don't have the correct length (length of BASE64 strings must be a multiple of 4, length os hexadecimal strings must be a multiple of 2).
If you still need to decode such strings, you can use option -p (--process). This option allows you to specify a Python function (that will be evaluated, so use only trusted input for this option) to modify the detected string before it is decoded).
You can use builtin function L4 (Length 4) for example: function L4 takes a string as input and truncates it if necessary, by removing characters from the end so that the length becomes a multiple of 4.
Example:
C:\Demo>base64dump.py -p L4 malformed_base64.vir

You can also provide your own function, for example via a lambda expression:
C:\Demo>base64dump.py -p "lambda x: x[:-1]" malformed_base64.vir

In this example, the lambda expression will remove one character from the end of the detected string.

With option -T (--headtail), output can be truncated to the first 10 lines and last 10 lines of output.

With option --jsonoutput base64dump.py will output selected content as a JSON object that can be piped into other tools that support this JSON format.

Option -c (--cut) allows for the partial selection of a datastream. Use this option to "cut out" part of the datastream.
The --cut option takes an argument to specify which section of bytes to select from the datastream. This argument is composed of 2 terms separated by a colon (:), like this:
termA:termB
termA and termB can be:
- nothing (an empty string)
- a positive decimal number; example: 10
- an hexadecimal number (to be preceded by 0x); example: 0x10
- a case sensitive string to search for (surrounded by square brackets and single quotes); example: ['MZ']
- an hexadecimal string to search for (surrounded by square brackets); example: [d0cf11e0]
If termA is nothing, then the cut section of bytes starts with the byte at position 0.
If termA is a number, then the cut section of bytes starts with the byte at the position given by the number (first byte has index 0).
If termA is a string to search for, then the cut section of bytes starts with the byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
If termB is nothing, then the cut section of bytes ends with the last byte.
If termB is a number, then the cut section of bytes ends with the byte at the position given by the number (first byte has index 0).
When termB is a number, it can have suffix letter l. This indicates that the number is a length (number of bytes), and not a position.
termB can also be a negative number (decimal or hexademical): in that case the position is counted from the end of the file. For example, :-5 selects the complete file except the last 5 bytes.
If termB is a string to search for, then the cut section of bytes ends with the last byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
No checks are made to assure that the position specified by termA is lower than the position specified by termB. This is left up to the user.
Search string expressions (ASCII and hexadecimal) can be followed by an instance (a number equal to 1 or greater) to indicate which instance needs to be taken. For example, ['ABC']2 will search for the second instance of string 'ABC'. If this instance is not found, then nothing is selected.
Search string expressions (ASCII and hexadecimal) can be followed by an offset (+ or - a number) to add (or substract) an offset to the found instance. For example, ['ABC']+3 will search for the first instance of string 'ABC' and then select the bytes after ABC (+ 3).
Finally, search string expressions (ASCII and hexadecimal) can be followed by an instance and an offset.
Examples:
This argument can be used to dump the first 256 bytes of a PE file located inside the datastream: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the datastream: [d0cf11e0]:
When this option is not used, the complete datastream is selected.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 78))

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

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def P23Chr(value):
    if type(value) == int:
        return chr(value)
    else:
        return value

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
            asciiDump += IFF(b >= 32 and b < 128, chr(b), '.')
        if countRLE > 0:
            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
        oDumpStream.Addline(self.CombineHexAscii(position + hexDump, asciiDump))
        return oDumpStream.Content()

    def Base64Dump(self, nowhitespace=False):
        encoded = binascii.b2a_base64(self.data)
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

def AsciiDump(data):
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data])

def Magic(data):
    magicPrintable = ''
    magicHex = ''
    for iter in range(4):
        if len(data) >= iter + 1:
            if P23Ord(data[iter]) >= 0x20 and P23Ord(data[iter]) < 0x7F:
                magicPrintable += P23Chr(data[iter])
            else:
                magicPrintable += '.'
            magicHex += '%02x' % P23Ord(data[iter])
    return magicPrintable, magicHex

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    countUniqueBytes = 0
    for iter in range(1, 0x21):
        if P23Chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
            countUniqueBytes += 1
    return sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def CalculateFileMetaData(data):
    dPrevalence = {}
    for iter in range(256):
        dPrevalence[iter] = 0
    for char in data:
        dPrevalence[P23Ord(char)] += 1

    fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    magicPrintable, magicHex = Magic(data[0:4])
    return CalculateChosenHash(data)[0], magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

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

class cHashCRC32():
    def __init__(self):
        self.crc32 = None

    def update(self, data):
        self.crc32 = zlib.crc32(data)

    def hexdigest(self):
        return '%08x' % (self.crc32 & 0xffffffff)

class cHashChecksum8():
    def __init__(self):
        self.sum = 0

    def update(self, data):
        if sys.version_info[0] >= 3:
            self.sum += sum(data)
        else:
            self.sum += sum(map(ord, data))

    def hexdigest(self):
        return '%08x' % (self.sum)

dSpecialHashes = {'crc32': cHashCRC32, 'checksum8': cHashChecksum8}

def GetHashObjects(algorithms):
    global dSpecialHashes

    dHashes = {}

    if algorithms == '':
        algorithms = os.getenv('DSS_DEFAULT_HASH_ALGORITHMS', 'md5')
    if ',' in algorithms:
        hashes = algorithms.split(',')
    else:
        hashes = algorithms.split(';')
    for name in hashes:
        if not name in dSpecialHashes.keys() and not name in hashlib.algorithms_available:
            print('Error: unknown hash algorithm: %s' % name)
            print('Available hash algorithms: ' + ' '.join([name for name in list(hashlib.algorithms_available)] + list(dSpecialHashes.keys())))
            return [], {}
        elif name in dSpecialHashes.keys():
            dHashes[name] = dSpecialHashes[name]()
        else:
            dHashes[name] = hashlib.new(name)

    return hashes, dHashes

def CalculateChosenHash(data):
    hashes, dHashes = GetHashObjects('')
    dHashes[hashes[0]].update(data)
    return dHashes[hashes[0]].hexdigest(), hashes[0]

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + b'{%d,}'
    return re.findall(regex % 4, data)

def ExtractStringsUNICODE(data):
    regex = b'((' + REGEX_STANDARD + b'\x00){%d,})'
    return [foundunicodestring.replace(b'\x00', b'') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def ExtractStrings(data):
    return ExtractStringsASCII(data) + ExtractStringsUNICODE(data)

def DumpFunctionStrings(data):
    return ''.join([extractedstring + '\n' for extractedstring in ExtractStrings(data)])

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

def Translate(expression):
    return lambda x: x.decode(expression)

def DecodeDataBase64(data, ProcessFunction):
    for base64string in re.findall(b'[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]+={0,2}', data):
        base64string = ProcessFunction(base64string)
        if len(base64string) % 4 == 0:
            try:
                yield (base64string, binascii.a2b_base64(base64string))
            except:
                continue

def DecodeDataBase85RFC1924(data, ProcessFunction):
    for base85string in re.findall(b'[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+\-;<=>?@^_`{|}~]+', data):
        base85string = ProcessFunction(base85string)
        try:
            yield (base85string, base64.b85decode(base85string))
        except:
            continue

def DecodeDataAscii85(data, ProcessFunction):
    for ascii85string in re.findall(b'''[!"#$%&'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuz-]+''', data):
        ascii85string = ProcessFunction(ascii85string)
        try:
            yield (ascii85string, base64.a85decode(ascii85string))
        except:
            continue

def DecodeDataHex(data, ProcessFunction):
    for hexstring in re.findall(b'[ABCDEFabcdef0123456789]+', data):
        hexstring = ProcessFunction(hexstring)
        if len(hexstring) % 2 == 0:
            try:
                yield (hexstring, binascii.a2b_hex(hexstring))
            except:
                continue

def DecodeBU(data):
    decoded = b''
    while data != b'':
        decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
        data = data[6:]
    return decoded

def DecodeDataBU(data, ProcessFunction):
    for bu in re.findall(br'(?:\\u[ABCDEFabcdef0123456789]{4})+', data):
        yield (bu, DecodeBU(bu))

def DecodeDataPU(data, ProcessFunction):
    for bu in re.findall(br'(?:%u[ABCDEFabcdef0123456789]{4})+', data):
        yield (bu, DecodeBU(bu))

def DecodeBX(data):
    decoded = b''
    while data != b'':
        decoded += binascii.a2b_hex(data[2:4])
        data = data[4:]
    return decoded

def DecodeDataBX(data, ProcessFunction):
    for bx in re.findall(br'(?:\\x[ABCDEFabcdef0123456789]{2})+', data):
        yield (bx, DecodeBX(bx))

def DecodeDataAH(data, ProcessFunction):
    for ah in re.findall(br'(?:&H[ABCDEFabcdef0123456789]{2})+', data):
        yield (ah, DecodeBX(ah))

def ReverseCount(data, count):
    result = b''
    while data != b'':
        part = data[0:count]
        data = data[count:]
        result = part + result
    return result

def DecodeZXLittleEndian(data):
    decoded = b''
    for hex in data.split(b'0x'):
        if hex == b'':
            continue
        if len(hex) % 2 == 1:
            hex = b'0' + hex
        decoded += binascii.a2b_hex(ReverseCount(hex, 2))
    return decoded

def DecodeDataZXLittleEndian(data, ProcessFunction):
    for zx in re.findall(br'(?:0x[ABCDEFabcdef0123456789]{1,8})+', data):
        yield (zx, DecodeZXLittleEndian(zx))

def DecodeZXBigEndian(data):
    decoded = b''
    for hex in data.split(b'0x'):
        if hex == b'':
            continue
        if len(hex) % 2 == 1:
            hex = b'0' + hex
        decoded += binascii.a2b_hex(hex)
    return decoded

def DecodeDataZXBigEndian(data, ProcessFunction):
    for zx in re.findall(br'(?:0x[ABCDEFabcdef0123456789]{1,8})+', data):
        yield (zx, DecodeZXBigEndian(zx))

def RemoveWhitespace(data):
    for whitespacecharacter in string.whitespace:
        data = data.replace(whitespacecharacter.encode(), b'')
    return data

def DecodeDataZXC(data, ProcessFunction):
    data = RemoveWhitespace(data)
    for hexstring in re.findall(br'(?:0x[ABCDEFabcdef0123456789]{2},)+0x[ABCDEFabcdef0123456789]{2}', data):
        try:
            yield (hexstring, binascii.a2b_hex(hexstring.replace(b'0x', b'').replace(b',', b'')))
        except:
            continue

def DecodeDataDecimal(data, ProcessFunction):
    #find decimal numbers separated by a single character that is not a digit
    for decimals in re.findall(br'(?:[0123456789]{1,3}[^0123456789])+[0123456789]{1,3}', data):
        dBytes = {}
        for byte in decimals:
            if byte < 0x30 or byte > 0x39:
                dBytes[byte] = dBytes.get(byte, 0) + 1
        if len(dBytes) > 0:
            # take the most frequent non-digit character as separator
            separator = bytes([sorted(dBytes.items(), key=operator.itemgetter(1), reverse=True)[0][0]])
            for decimalstring in re.findall((br'(?:[0123456789]{1,3}\x%02x' % separator[0]) + br')+[0123456789]{1,3}', decimals):
                try:
                    yield (decimalstring, bytes([int(decimal) for decimal in decimalstring.split(separator)]))
                except:
                    continue

def NETBIOSDecode(netbios):
    dTranslate = {
        ord(b'A'): ord(b'0'),
        ord(b'B'): ord(b'1'),
        ord(b'C'): ord(b'2'),
        ord(b'D'): ord(b'3'),
        ord(b'E'): ord(b'4'),
        ord(b'F'): ord(b'5'),
        ord(b'G'): ord(b'6'),
        ord(b'H'): ord(b'7'),
        ord(b'I'): ord(b'8'),
        ord(b'J'): ord(b'9'),
        ord(b'K'): ord(b'A'),
        ord(b'L'): ord(b'B'),
        ord(b'M'): ord(b'C'),
        ord(b'N'): ord(b'D'),
        ord(b'O'): ord(b'E'),
        ord(b'P'): ord(b'F'),
    }
    return binascii.a2b_hex(bytes([dTranslate[char] for char in netbios]))

def DecodeDataNETBIOS(data, ProcessFunction):
    #find A - P sequence of letters
    for netbiosstring in re.findall(b'[ABCDEFGHIJKLMNOP]+', data):
        netbiosstring = ProcessFunction(netbiosstring)
        if len(netbiosstring) % 2 == 0:
            try:
                yield (netbiosstring, NETBIOSDecode(netbiosstring))
            except:
                continue

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

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, decoderdir, verbose):
    if decoders == '':
        return

    if decoderdir == '':
        scriptPath = os.path.dirname(sys.argv[0])
    else:
        scriptPath = decoderdir

    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e

class cIdentity(cDecoderParent):
    name = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ''

def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()

def PrintWarningSelection(select, selectionCounter):
    if select != '' and selectionCounter == 0:
        print('Warning: no decoding was selected with expression %s' % select)

def L4(data):
    modulus = len(data) % 4
    if modulus == 0:
        return data
    else:
        return data[:-modulus]

def AvailableEncodings():
    global dEncodings

    result = ['Available encodings (use "all" to try all encodings):']
    for key, value in dEncodings.items():
        result.append(' %s -> %s' % (key, value[0]))
    return result

def BASE64Dump(filename, options):
    global decoders
    global dEncodings

    if options.encoding == '?' :
        for line in AvailableEncodings():
            print(line)
        return

    if options.encoding != 'all' and not options.encoding in dEncodings:
        print('Error: invalid encoding: %s' % options.encoding)
        print('Valid encodings:')
        for key, value in dEncodings.items():
            print(' %s -> %s' % (key, value[0]))
        return

    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        if sys.version_info[0] >= 3:
            oDataIO = DataIO(sys.stdin.buffer.read())
        else:
            oDataIO = DataIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', MALWARE_PASSWORD)
        oDataIO = DataIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oDataIO = DataIO(open(filename, 'rb').read())

    if options.dump:
        DumpFunction = lambda x:x
        IfWIN32SetBinary(sys.stdout)
    elif options.hexdump:
        DumpFunction = HexDump
    elif options.asciidump:
        DumpFunction = HexAsciiDump
    elif options.asciidumprle:
        DumpFunction = lambda x: HexAsciiDump(x, True)
    elif options.strings:
        DumpFunction = DumpFunctionStrings
    elif options.translate != '':
        DumpFunction = Translate(options.translate)
    else:
        DumpFunction = None

    selectionCounter = 0
    if options.jsonoutput:
        jsonObject = []

    if options.encoding == 'all' or options.yara != None:
        formatString = '%3s  %-7s %-16s %-16s %-32s'
        columnNames = ('Enc', 'Size', 'Encoded', 'Decoded', '%s decoded' % CalculateChosenHash(b'')[1])
        print(formatString % columnNames)
        print(formatString % tuple(['-' * len(s) for s in columnNames]))
    elif options.select == '' and not options.jsonoutput:
        formatString = '%-2s  %-7s %-16s %-16s %-32s'
        columnNames = ('ID', 'Size', 'Encoded', 'Decoded', '%s decoded' % CalculateChosenHash(b'')[1])
        print(formatString % columnNames)
        print(formatString % tuple(['-' * len(s) for s in columnNames]))

    data = oDataIO.read()
    if options.ignorewhitespace:
        data = RemoveWhitespace(data)
    for ignore in options.ignore:
        data = data.replace(bytes([P23Ord(ignore)]), b'')
    for index in range(len(options.ignore)):
        data = data.replace(options.ignore.encode()[index:index + 1], b'')
    bytesignorehex = binascii.a2b_hex(options.ignorehex)
    for index in range(len(bytesignorehex)):
        data = data.replace(bytesignorehex[index:index + 1], b'')
    if options.ignorenullbytes:
        previous_char_was_zero = False
        result = ''
        for char in data:
            if char == '\x00':
                if previous_char_was_zero:
                    result += char
                previous_char_was_zero = True
            else:
                result += char
                previous_char_was_zero = False
        data = result
        result = None
    dDecodedData = {}

    ProcessFunction = lambda x: x
    if options.process != '':
        ProcessFunction = eval(options.process)

    rules = None
    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)
        for encoding in dEncodings:
            for encodeddata, decodeddata in dEncodings[encoding][1](data, ProcessFunction):
                if options.number and len(decodeddata) < options.number:
                    continue
                if options.unique and decodeddata in dDecodedData:
                    continue
                dDecodedData[decodeddata] = True
                line = '%3s: %7d %-16s %-16s %s' % (encoding, len(encodeddata), encodeddata[0:16].decode('latin'), AsciiDump(decodeddata[0:16]), CalculateChosenHash(decodeddata)[0])
                oDecoders = [cIdentity(decodeddata, None)]
                for cDecoder in decoders:
                    try:
                        oDecoder = cDecoder(decodeddata, options.decoderoptions)
                        oDecoders.append(oDecoder)
                    except Exception as e:
                        print('Error instantiating decoder: %s' % cDecoder.name)
                        if options.verbose:
                            raise e
                        return
                for oDecoder in oDecoders:
                    while oDecoder.Available():
                        for result in rules.match(data=oDecoder.Decode()):
                            if line != None:
                                print(line)
                                line = None
                            print('     YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (decoder: %s)' % oDecoder.Name()), result.rule))
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('     %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('      %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                    print('      %s' % repr(stringdata[2]))

    elif options.encoding == 'all':
        report = []
        for encoding in dEncodings:
            for encodeddata, decodeddata in dEncodings[encoding][1](data, ProcessFunction):
                if options.number and len(decodeddata) < options.number:
                    continue
                if options.unique and decodeddata in dDecodedData:
                    continue
                dDecodedData[decodeddata] = True
                report.append([len(encodeddata), '%3s: %7d %-16s %-16s %s' % (encoding, len(encodeddata), encodeddata[0:16].decode('latin'), AsciiDump(decodeddata[0:16]), CalculateChosenHash(decodeddata)[0])])
        for key, value in sorted(report):
            print(value)
    else:
        decodedData = list(dEncodings[options.encoding][1](data, ProcessFunction))
        if options.select == 'L':
            largestSize = -1
            largestCounter = None
            for index, (encodeddata, decodeddata) in enumerate(decodedData):
                if len(encodeddata) > largestSize:
                    largestSize = len(encodeddata)
                    largestCounter = index + 1
            options.select = str(largestCounter)
        counter = 1
        for encodeddata, decodeddata in decodedData:
            if options.number and len(decodeddata) < options.number:
                continue
            if options.unique and decodeddata in dDecodedData:
                continue
            dDecodedData[decodeddata] = True
            if options.select == '':
                if options.jsonoutput:
                    jsonObject.append({'id': counter, 'name': encodeddata[0:16].decode('latin'), 'content': binascii.b2a_base64(decodeddata).strip(b'\n').decode()})
                else:
                    print('%2d: %7d %-16s %-16s %s' % (counter, len(encodeddata), encodeddata[0:16].decode('latin'), AsciiDump(decodeddata[0:16]), CalculateChosenHash(decodeddata)[0]))
            elif ('%s' % counter) == options.select or options.select == 'a':
                if len(decoders) > 1:
                    print('Error: provide only one decoder when using option select')
                    return
                selectionCounter += 1
                if options.jsonoutput:
                    jsonObject.append({'id': counter, 'name': encodeddata[0:16].decode('latin'), 'content': binascii.b2a_base64(decodeddata).strip(b'\n').decode()})
                elif DumpFunction == None:
                    filehash, magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateFileMetaData(CutData(decodeddata, options.cut)[0])
                    print('Info:')
                    print(' %s: %s' % (CalculateChosenHash(b'')[1], filehash))
                    print(' %s: %d' % ('Filesize', fileSize))
                    print(' %s: %f' % ('Entropy', entropy))
                    print(' %s: %d (%.2f%%)' % ('Unique bytes', countUniqueBytes, countUniqueBytes / 2.560))
                    print(' %s: %s' % ('Magic HEX', magicHex))
                    print(' %s: %s' % ('Magic ASCII', magicPrintable))
                    print(' %s: %s' % ('Null bytes', countNullByte))
                    print(' %s: %s' % ('Control bytes', countControlBytes))
                    print(' %s: %s' % ('Whitespace bytes', countWhitespaceBytes))
                    print(' %s: %s' % ('Printable bytes', countPrintableBytes))
                    print(' %s: %s' % ('High bytes', countHighBytes))
                else:
                    StdoutWriteChunked(HeadTail(DumpFunction(DecodeFunction(decoders, options, CutData(decodeddata, options.cut)[0])), options.headtail))
            counter += 1

    if options.jsonoutput:
        print(json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': jsonObject}))
    else:
        PrintWarningSelection(options.select, selectionCounter)

    return 0

def Main():
    global dEncodings

    dEncodings = {
        'b64': ('BASE64, example: TVqQAAMAAAAEAAAA...', DecodeDataBase64),
        'bu': ('\\u UNICODE, example: \\u9090\\ueb77...', DecodeDataBU),
        'pu': ('% UNICODE, example: %u9090%ueb77...', DecodeDataPU),
        'hex': ('hexadecimal, example: 6D6573736167652C...', DecodeDataHex),
        'bx': ('\\x hexadecimal, example: \\x90\\x90...', DecodeDataBX),
        'ah': ('&H hexadecimal, example: &H90&H90...', DecodeDataAH),
        'zxle': ('0x hexadecimal little-endian, example: 0x909090900xeb77...', DecodeDataZXLittleEndian),
        'zxbe': ('0x hexadecimal big-endian, example: 0x909090900x77eb...', DecodeDataZXBigEndian),
        'zxc': ('0x hexadecimal 2 digits, comma-separated, example: 0x90,0x90,0x90,0x90...', DecodeDataZXC),
        'dec': ('decimal numbers, separated by an arbitrary separator, example: 80;75;3;4...', DecodeDataDecimal),
        'nb': ('NETBIOS, uppercase letters from A to P, example: ENFKOIAA', DecodeDataNETBIOS),
        'b85': ('BASE85 RFC 1924, example: X>D+Ca&#bLba`-Pb31o...', DecodeDataBase85RFC1924),
        'a85': ('ASCII85, example: BOu!rD]...', DecodeDataAscii85),
    }

    helpEncodings = '\n'.join(AvailableEncodings())
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__  + '\n' + helpEncodings, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-e', '--encoding', default='b64', help='select encoding to use, use "all" to try all encodings (default base64)')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all, L for largest)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-S', '--strings', action='store_true', default=False, help='perform strings dump')
    oParser.add_option('-t', '--translate', type=str, default='', help='string translation, like utf16 or .decode("utf8")')
    oParser.add_option('-n', '--number', type=int, default=None, help='minimum number of bytes in decoded data')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-w', '--ignorewhitespace', action='store_true', default=False, help='ignore whitespace')
    oParser.add_option('-u', '--unique', action='store_true', default=False, help='do not repeat identical decoded data')
    oParser.add_option('-z', '--ignorenullbytes', action='store_true', default=False, help='ignore null (zero) bytes')
    oParser.add_option('-i', '--ignore', type=str, default='', help='characters to ignore')
    oParser.add_option('-I', '--ignorehex', type=str, default='', help='characters to ignore (hexadecimal)')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file, directory or #rule to check data (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors and YARA rules')
    oParser.add_option('--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('-T', '--headtail', action='store_true', default=False, help='do head & tail')
    oParser.add_option('-p', '--process', type=str, default='', help='Python function to process encodings prior to decoding (like L4, lambda bytes: bytes[:-1], ...)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if options.number != None and options.select == 'L':
        print('Error: option number and select L are mutually exclusive')
        return 0
    if options.unique and options.select == 'L':
        print('Error: option unique and select L are mutually exclusive')
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
        return BASE64Dump('', options)
    else:
        return BASE64Dump(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
