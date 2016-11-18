#!/usr/bin/env python

__description__ = 'ZIP dump utility'
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2016/11/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2014/04/30: added timestamp
  2014/10/07: added magic values and metadata; added option dumpall, hexdumpall and asciidumpall
  2014/10/09: refactoring, added option extra
  2014/10/13: fixed whitespace counter bug; -o bug
  2014/10/26: refactoring
  2014/11/09: added option -p
  2014/12/21: 0.0.2: Added YARA support; added decoders
  2015/01/08: 0.0.3: Added support for multiple YARA rule files
  2015/02/09: Added option yarastrings
  2015/06/08: Fix HexAsciiDump
  2015/07/21: filename = '*'
  2015/09/12: if the ZIP file contains a single ZIP file, then the contained ZIP file is dumped; added --cut
  2015/09/13: added option -r and -z
  2015/09/22: added --man
  2015/09/29: bug fixes
  2015/11/17: added support for :-number in --cut option; added -E option
  2016/05/26: refactoring and man
  2016/05/29: continue man, updated cut option
  2016/11/15: 0.0.4: Added support ZIP comment
  2016/11/16: added Unique bytes

Todo:
"""

import optparse
import zipfile
import hashlib
import signal
import sys
import os
import cStringIO
import string
import math
import binascii
import re
import textwrap
try:
    import yara
except:
    pass

QUOTE = '"'

def PrintManual():
    manual = '''
Manual:

zipdump is a tool to analyze ZIP files.
The ZIP file can be provided as an argument, via stdin (piping) and it may also be contained in a (password protected) ZIP file.

When providing zipdump with a file to analyze, it will report on the content of the ZIP file, like in this example:
C:\Demo>zipdump.py example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26
    2 readme.txt           0 2015-11-24 19:40:12

The first column, Index, is an index that zipdump assigns to each file inside the ZIP file. You can use it with option -s (select) to select a file for further analysis.
Filename is the filename of the contained file.
Encrypted is a flag indicating if the file is encrypted (1) or not (0).
And the last column (Timestamp) is the timestamp of the file inside the archive.

Option -s takes the index number or the filename to select a file.

By default, the separator used to delimit columns is the space character. When the default separator is used, padding is added to lign up the columns. Another separator character can be selected with option -S. No padding is used when the separator is provided (even if it is the space character).
C:\Demo>zipdump.py -S ; example.zip
Index;Filename;Encrypted;Timestamp;
1;Dialog42.exe;0;2012-02-25 12:08:26;
2;readme.txt;0;2015-11-24 19:40:12;

When a file is selected, the properties of this file are displayed:
C:\Demo>zipdump.py -s 1 example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26

The content of the selected file can also be dumped.
Use option -x to perform an hexdump:
C:\Demo>zipdump.py -s 1 -x example.zip
4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
...

Use option -a to perform an ascii/hexdump:
C:\Demo>zipdump.py -s 1 -a example.zip
00000000: 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00  MZP.............
00000010: B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00  +.......@.......
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...

Use option -d to perform a raw dump:
C:\Demo>zipdump.py -s 2 -d example.zip
test

A raw dump is useful to pipe the output into another command:
C:\Demo>zipdump.py -s 1 -d example.zip | pecheck.py
PE check for '':
Entropy: 6.425034 (Min=0.0, Max=8.0)
MD5     hash: 9b7f8260724e2cb643ad0729ec995b40
...

When options -x, -a or -d are used without selecting a file (option -s), the first file in the ZIP file is selected and dumped.
When options -X, -A or -D are used without selecting a file (option -s), all files in the ZIP file are selected and dumped.

The output produced by zipdump.py can de written to a file with option -o.

If the ZIP file is password protected, zipdump.py will try with password 'infected'. Option -p can be used to provide a different password to open the ZIP file.

If the ZIP file contains a single ZIP file, the contained ZIP file will be considered to be the ZIP file to analyze. To prevent this, use option -r. Option -r handles the contained ZIP file as a regular file.

Option -z can be used to include the name of the zipfile in the report:
C:\Demo>zipdump.py -z -S ; example.zip
Index;Zipfilename;Filename;Encrypted;Timestamp;
1;example.zip;Dialog42.exe;0;2012-02-25 12:08:26;
2;example.zip;readme.txt;0;2015-11-24 19:40:12;

This can be useful when reports of many ZIP files are merged together.

Option -e extends the amount of information reported:
C:\Demo>zipdump.py -e example.zip
Index Filename     Encrypted Timestamp           MD5                              Filesize Entropy       Unique bytes Magic HEX Magic ASCII Null bytes Control bytes Whitespace bytes Printable bytes High bytes 
    1 Dialog42.exe         0 2012-02-25 12:08:26 9b7f8260724e2cb643ad0729ec995b40    58120 6.42503434625          256 4d5a5000  MZP.             13014          6403             1678           19366      17659 
    2 readme.txt           0 2015-11-24 19:40:12 098f6bcd4621d373cade4e832627b4f6        4 1.5                      3  74657374 test                 0             0                0               4          0 

Columns MD5, Filesize and Entropy should be self-explanatory.
Unique bytes counts the number of unique, different byte values contained in the file.
The Magic columns (HEX and ASCII) report the first 4 bytes of the file.
The remaining columns provide more statistical data about the contained file. They count the number of bytes of a particular type found inside the contained file. The byte types are: null bytes, control bytes, whitespace, printable bytes and high bytes.

If you need other data than displayed by option -e, use option -E (extra). This option takes a parameter describing the extra data that needs to be calculated and displayed for each file. The following variables are defined:
  %INDEX%: the index of the file
  %ZIPFILENAME%: the filename of the ZIP container
  %FILENAME%: the filename of the contained file
  %ENCRYPTED%: encrypted indicator
  %TIMESTAMP%: timestamp
  %LENGTH%': the length of the file
  %MD5%: calculates MD5 hash
  %SHA1%: calculates SHA1 hash
  %SHA256%: calculates SHA256 hash
  %ENTROPY%: calculates entropy
  %HEADHEX%: display first 20 bytes of the file as hexadecimal
  %HEADASCII%: display first 20 bytes of the file as ASCII
  %TAILHEX%: display last 20 bytes of the file as hexadecimal
  %TAILASCII%: display last 20 bytes of the file as ASCII
  %HISTOGRAM%: calculates a histogram
                 this is the prevalence of each byte value (0x00 through 0xFF)
                 at least 3 numbers are displayed separated by a comma:
                 number of values with a prevalence > 0
                 minimum values with a prevalence > 0
                 maximum values with a prevalence > 0
                 each value with a prevalence > 0
  %BYTESTATS%: calculates byte statistics
                 byte statistics are 5 numbers separated by a comma:
                 number of NULL bytes
                 number of control bytes
                 number of whitespace bytes
                 number of printable bytes
                 number of high bytes

Example adding the SHA256 hash to the report:
C:\Demo>zipdump.py -E "%SHA256%" example.zip
Index Filename     Encrypted Timestamp           
    1 Dialog42.exe         0 2012-02-25 12:08:26 0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
    2 readme.txt           0 2015-11-24 19:40:12 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

The parameter for -E may contain other text than the variables, which will be printed. Escape characters \\n and \\t are supported.
Example displaying the MD5 and SHA256 hash per file, separated by a - character:
C:\Demo>zipdump.py -E "%MD5%-%SHA256%" example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26 9b7f8260724e2cb643ad0729ec995b40-0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
    2 readme.txt           0 2015-11-24 19:40:12 098f6bcd4621d373cade4e832627b4f6-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

If the extra parameter starts with !, then it replaces the complete output line (in stead of being appended to the output line).
Example:
C:\Demo>zipdump.py -E "!%FILENAME%;%SHA256%" example.zip
Dialog42.exe;0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
readme.txt;9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

To include extra data with each use of zipdump, define environment variable ZIPDUMP_EXTRA with the parameter that should be passed to -E. When environment variable ZIPDUMP_EXTRA is defined, option -E can be ommited. When option -E is used together with environment variable ZIPDUMP_EXTRA, the parameter of option -E is used and the environment variable is ignored.

zipdump supports YARA rules. Installation of the YARA Python module is not mandatory if you don't use YARA rules.
You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files.
All files inside the ZIP file are scanned with the provided YARA rules, you can not use option -s to select an individual file.

Example:
C:\Demo>zipdump.py -y contains_pe_file.yara example.zip
Index Filename     Decoder YARA namespace        YARA rule        
    1 Dialog42.exe         contains_pe_file.yara Contains_PE_File 

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) inside ZIP files. The rule triggered for file 1, because it contains an EXE file.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
C:\Demo>zipdump.py -y contains_pe_file.yara --yarastrings example.zip
Index Filename     Decoder YARA namespace        YARA rule        
    1 Dialog42.exe         contains_pe_file.yara Contains_PE_File 000000 $a 4d5a 'MZ' 

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

To deal with encoded files, zipdump supports decoders. A decoder is a type of plugin, that will bruteforce a type of encoding on each file. For example, decoder_xor1 will encode each file via XOR and a key of 1 byte. So effectively, 256 different encodings of the file will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
C:\Demo>zipdump.py -y contains_pe_file.yara -C decoder_xor1 example.zip
Index Filename            Decoder             YARA namespace        YARA rule        
    1 Dialog42.exe                            contains_pe_file.yara Contains_PE_File 
    3 Dialog42.exe.XORx14 XOR 1 byte key 0x14 contains_pe_file.yara Contains_PE_File 

The YARA rule triggers on file 3. It contains a PE file encoded via XORing each byte with key 0x14.

You can specify more than one decoder separated by a comma ,.
C:\Demo>zipdump.py -y contains_pe_file.yara -C decoder_xor1,decoder_rol1,decoder_add1 example.zip

Some decoders take options, to be provided with option --decoderoptions.

Use option -v to have verbose error messages when debugging your decoders.

Option -c (--cut) allows for the partial selection of a file. Use this option to "cut out" part of the file.
The --cut option takes an argument to specify which section of bytes to select from the file. This argument is composed of 2 terms separated by a colon (:), like this:
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
This argument can be used to dump the first 256 bytes of a PE file located inside the file: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the file: [d0cf11e0]:
When this option is not used, the complete file is selected.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 78))

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line +'\n')

dumplinelength = 16

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

def YARACompile(fileordirname):
    dFilepaths = {}
    if os.path.isdir(fileordirname):
        for root, dirs, files in os.walk(fileordirname):
            for file in files:
                filename = os.path.join(root, file)
                dFilepaths[filename] = filename
    else:
        for filename in ProcessAt(fileordirname):
            dFilepaths[filename] = filename
    return yara.compile(filepaths=dFilepaths)

class cDumpStream():
    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text

def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (16 - len(asciiDump)))) + asciiDump

def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump+= ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        sys.stdout.flush()
        data = data[10000:]

def Magic(data):
    magicPrintable = ''
    magicHex = ''
    for iter in range(4):
        if len(data) >= iter + 1:
            if ord(data[iter]) >= 0x20 and ord(data[iter]) < 0x7F:
                magicPrintable += data[iter]
            else:
                magicPrintable += '.'
            magicHex += '%02x' % ord(data[iter])
    return magicPrintable, magicHex

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    countUniqueBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
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
        dPrevalence[ord(char)] += 1

    fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    magicPrintable, magicHex = Magic(data[0:4])
    return hashlib.md5(data).hexdigest(), magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec open(decoder, 'r') in globals(), globals()
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

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

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
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-]\d+)?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[\'(.+?)\'\](\d+)?([+-]\d+)?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        return CUTTERM_FIND, (oMatch.group(1), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

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

def Find(data, value, nth):
    position = -1
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return stream

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return stream

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ''
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
        positionEnd = Find(stream, valueRight[0], valueRight[1])
        if positionEnd == -1:
            return ''
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return stream[positionBegin:positionEnd]

def ExtraInfoMD5(data):
    if data == None:
        return ''
    return hashlib.md5(data).hexdigest()

def ExtraInfoSHA1(data):
    if data == None:
        return ''
    return hashlib.sha1(data).hexdigest()

def ExtraInfoSHA256(data):
    if data == None:
        return ''
    return hashlib.sha256(data).hexdigest()

def ExtraInfoENTROPY(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%f' % entropy

def ExtraInfoHEADHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[:16])

def ExtraInfoHEADASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(ord(b) >= 32, b, '.') for b in data[:16]])

def ExtraInfoTAILHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[-16:])

def ExtraInfoTAILASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(ord(b) >= 32, b, '.') for b in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[ord(char)] += 1
    result = []
    count = 0
    minimum = None
    maximum = None
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            result.append('0x%02x:%d' % (iter, dPrevalence[iter]))
            count += 1
            if minimum == None:
                minimum = iter
            else:
                minimum = min(minimum, iter)
            if maximum == None:
                maximum = iter
            else:
                maximum = max(maximum, iter)
    result.insert(0, '%d' % count)
    result.insert(1, IFF(minimum == None, '', '0x%02x' % minimum))
    result.insert(2, IFF(maximum == None, '', '0x%02x' % maximum))
    return ','.join(result)

def ExtraInfoBYTESTATS(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def GenerateExtraInfo(extra, index, zipfilename, filename, encrypted, timestamp, stream):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
    dExtras = {'%INDEX%': lambda x: '%d' % index,
               '%ZIPFILENAME%': lambda x: zipfilename,
               '%FILENAME%': lambda x: filename,
               '%ENCRYPTED%': lambda x: '%d' % encrypted,
               '%TIMESTAMP%': lambda x: timestamp,
               '%LENGTH%': lambda x: IFF(stream == None, '', lambda: '%d' % len(stream)),
               '%MD5%': ExtraInfoMD5,
               '%SHA1%': ExtraInfoSHA1,
               '%SHA256%': ExtraInfoSHA256,
               '%ENTROPY%': ExtraInfoENTROPY,
               '%HEADHEX%': ExtraInfoHEADHEX,
               '%HEADASCII%': ExtraInfoHEADASCII,
               '%TAILHEX%': ExtraInfoTAILHEX,
               '%TAILASCII%': ExtraInfoTAILASCII,
               '%HISTOGRAM%': ExtraInfoHISTOGRAM,
               '%BYTESTATS%': ExtraInfoBYTESTATS,
              }
    for variable in dExtras:
        if variable in extra:
            extra = extra.replace(variable, dExtras[variable](stream))
    return extra.replace(r'\t', '\t').replace(r'\n', '\n')

def Format(string, length):
    spaces = ' ' * (length - len(string))
    if string.isdigit():
        return spaces + string
    else:
        return string + spaces

def PrintOutput(output, outputExtraInfo, extra, separator, quote, fOut):
    if extra.startswith('!'):
        for line in outputExtraInfo[1:]:
            Print(line, fOut)
    else:
        if separator != '':
            for i in range(len(output)):
                Print(MakeCSVLine(output[i], separator, quote) + separator + outputExtraInfo[i], fOut)
        else:
            stringsOutput = [map(ToString, row) for row in output]
            lengthMaxRow = max([len(row) for row in output])
            lengthsMax = [0 for i in range(lengthMaxRow)]
            for i in range(lengthMaxRow):
                for row in stringsOutput:
                    if i < len(row):
                        lengthsMax[i] = max(lengthsMax[i], len(row[i]))
            for i in range(len(stringsOutput)):
                Print(' '.join([Format(stringsOutput[i][j], lengthsMax[j]) for j in range(len(stringsOutput[i]))]) + ' ' + outputExtraInfo[i], fOut)

def IsNumeric(value):
    if value == '':
        return False
    for c in value:
        if c < '0' or c > '9':
            return False
    return True

def DecideToSelect(selectvalue, counter, zipfilename):
    if selectvalue == '':
        return True
    if IsNumeric(selectvalue) and selectvalue == str(counter):
        return True
    return selectvalue == zipfilename

def ZIPDump(zipfilename, options):
    global decoders
    decoders = []
    LoadDecoders(options.decoders, True)

    FixPipe()
    if zipfilename == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        oZipfile = zipfile.ZipFile(cStringIO.StringIO(sys.stdin.read()), 'r')
    else:
        oZipfile = zipfile.ZipFile(zipfilename, 'r')
    if not options.regular and len(oZipfile.infolist()) == 1:
        try:
            if oZipfile.open(oZipfile.infolist()[0], 'r', options.password).read(2) == 'PK':
                oZipfile2 = zipfile.ZipFile(cStringIO.StringIO(oZipfile.open(oZipfile.infolist()[0], 'r', options.password).read()), 'r')
                oZipfile.close()
                oZipfile = oZipfile2
        except:
            pass

    if options.output:
        fOut = open(options.output, 'w')
    else:
        fOut = None

    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules = YARACompile(options.yara)

    if options.dump or options.dumpall or options.hexdump or options.hexdumpall or options.asciidump or options.asciidumpall:
        if options.dump or options.dumpall:
            DumpFunction = lambda x:x
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        elif options.hexdump or options.hexdumpall:
            DumpFunction = HexDump
        else:
            DumpFunction = HexAsciiDump
        counter = 0
        for oZipInfo in oZipfile.infolist():
            counter += 1
            if DecideToSelect(options.select, counter, oZipInfo.filename):
                file = oZipfile.open(oZipInfo, 'r', options.password)
                if options.output:
                    fOut.write(DumpFunction(CutData(file.read(), options.cut)))
                else:
                    StdoutWriteChunked(DumpFunction(CutData(file.read(), options.cut)))
                file.close()
                if options.select == '' and (options.dump or options.hexdump or options.asciidump):
                    break
    else:
        if oZipfile.comment != '':
            Print(oZipfile.comment, fOut)
        outputRows = []
        outputExtraInfo = ['']
        headers = ['Index']
        if options.zipfilename:
            headers.append('Zipfilename')
        headers.append('Filename')
        if options.yara:
            headers.extend(['Decoder', 'YARA namespace', 'YARA rule'])
        else:
            if options.extended:
                headers.extend(['Encrypted', 'Timestamp', 'MD5', 'Filesize', 'Entropy', 'Unique bytes', 'Magic HEX', 'Magic ASCII', 'Null bytes', 'Control bytes', 'Whitespace bytes', 'Printable bytes', 'High bytes'])
            else:
                headers.extend(['Encrypted', 'Timestamp'])
        outputRows.append(headers)
        counter = 0
        for oZipInfo in oZipfile.infolist():
            counter += 1
            if DecideToSelect(options.select, counter, oZipInfo.filename):
                file = oZipfile.open(oZipInfo, 'r', options.password)
                filecontent = file.read()
                file.close()
                encrypted = oZipInfo.flag_bits & 1
                timestamp = '%04d-%02d-%02d %02d:%02d:%02d' % oZipInfo.date_time
                if options.yara == None:
                    if options.extended:
                        filehash, magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateFileMetaData(filecontent)
                        row = [oZipInfo.filename, encrypted, timestamp, filehash, fileSize, entropy, countUniqueBytes, magicHex, magicPrintable, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes]
                    else:
                        row = [oZipInfo.filename, encrypted, timestamp]
                    if options.zipfilename:
                        row.insert(0, zipfilename)
                    row.insert(0, counter)
                    outputRows.append(row)
                    outputExtraInfo.append(GenerateExtraInfo(options.extra, counter, zipfilename, oZipInfo.filename, encrypted, timestamp, filecontent))
                else:
                    oDecoders = [cIdentity(filecontent, None)]
                    for cDecoder in decoders:
                        try:
                            oDecoder = cDecoder(filecontent, options.decoderoptions)
                            oDecoders.append(oDecoder)
                        except Exception as e:
                            print('Error instantiating decoder: %s' % cDecoder.name)
                            if options.verbose:
                                raise e
                            return
                    for oDecoder in oDecoders:
                        while oDecoder.Available():
                            for result in rules.match(data=oDecoder.Decode()):
                                row = [oZipInfo.filename, oDecoder.Name(), result.namespace, result.rule]
                                if options.zipfilename:
                                    row.insert(0, zipfilename)
                                row.insert(0, counter)
                                if options.yarastrings:
                                    for stringdata in result.strings:
                                        row.append('%06x' % stringdata[0])
                                        row.append(stringdata[1])
                                        row.append(binascii.hexlify(stringdata[2]))
                                        row.append(repr(stringdata[2]))
                                outputExtraInfo.append('')
                                outputRows.append(row)

        PrintOutput(outputRows, outputExtraInfo, options.extra, options.separator, QUOTE, fOut)

    if fOut:
        fOut.close()
    oZipfile.close()

def OptionsEnvironmentVariables(options):
    if options.extra == '':
        options.extra = os.getenv('ZIPDUMP_EXTRA', options.extra)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [zipfile]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select index nr or name')
    oParser.add_option('-S', '--separator', default='', help='Separator character (default )')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump of first file or selected file')
    oParser.add_option('-D', '--dumpall', action='store_true', default=False, help='perform dump of all files or selected file')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump of first file or selected file')
    oParser.add_option('-X', '--hexdumpall', action='store_true', default=False, help='perform hex dump of all files or selected file')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump of first file or selected file')
    oParser.add_option('-A', '--asciidumpall', action='store_true', default=False, help='perform ascii dump of all files or selected file')
    oParser.add_option('-e', '--extended', action='store_true', default=False, help='report extended information')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-y', '--yara', help="YARA rule file (or directory or @file) to check files (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-C', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-r', '--regular', action='store_true', default=False, help='if the ZIP file contains a single ZIP file, handle it like a regular (non-ZIP) file')
    oParser.add_option('-z', '--zipfilename', action='store_true', default=False, help='include the filename of the ZIP file in the output')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: ZIPDUMP_EXTRA)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-c) is invalid: %s' % options.cut)
        return 0

    OptionsEnvironmentVariables(options)

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        ZIPDump('', options)
    else:
        ZIPDump(args[0], options)

if __name__ == '__main__':
    Main()
