#!/usr/bin/env python

__description__ = 'EML dump utility'
__author__ = 'Didier Stevens'
__version__ = '0.0.13'
__date__ = '2023/09/18'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2015/03/01: added Multipart flag
  2015/05/08: 0.0.2 added ZIP support
  2015/05/20: 0.0.3 added length; added type selection
  2015/06/08: Fix HexAsciiDump; added YARA support
  2015/09/12: added option -c
  2015/09/14: added option -m
  2015/09/21: reviewed man
  2015/11/08: 0.0.4 added option -E and environment variable EMLDUMP_EXTRA
  2015/11/09: continue -E
  2015/11/17: 0.0.5 added support for :-number in --cut option
  2016/01/08: 0.0.6 added warning when first lines do not contain a field
  2016/01/24: updated CutData
  2016/02/28: 0.0.7 added option -f
  2016/03/02: 0.0.8 extra deobfuscation code for option -f
  2016/04/13: 0.0.9 changed handling of obfuscating lines
  2017/07/21: 0.0.10 added filename to parts
  2020/11/21: 0.0.11 Python 3 support; updated cutting; updated yara; added selection warning
  2023/08/29: 0.0.12 bug fixes; added option -F
  2023/09/18: 0.0.13 added option --jsonoutput

Todo:
"""

import optparse
import email
import hashlib
import signal
import sys
import os
import zipfile
import re
import binascii
import textwrap
import string
import math
import json
try:
    import yara
except:
    pass

MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

emldump is a tool to analyze MIME files.
The MIME file can be provided as an argument, via stdin (piping) and it may also be contained in a (password protected) ZIP file.
When emldump runs on a MIME file without any options, it reports the different parts in the MIME file. Like in this example:

emldump.py sample.vir
1: M         multipart/alternative
2:       610 text/plain
3: M         multipart/related
4:      1684 text/html
5:    133896 application/octet-stream

The first number is an index added by emldump (this index does not come from the MIME file). This index can be used to select a part.
If a part has an M indicator, then it is a multipart and can not be selected.
Next is the number of bytes in the part, and the MIME type of the part.

Some MIME files start with one or more lines that have to be skipped (because they don't contain a RFC822 field). For example e-mails saved with Lotus Notes start with one line of info. A warning will be issued for such files:

emldump.py example-header-2.eml
Warning: the first 2 lines do not contain a field.
1:    158034 text/plain

Skipping these first lines can be done with option -H.

Some MIME files are obfuscated, for example they contain long lines of random letters and numbers. The filter option will filter out obfuscating lines: the filter option filters out first lines that are not fields (like with option -H), and every line that is longer than 100 characters.

Option fix (-F) will fix some obfuscations (for the moment: mime-version obfuscation).

A particular part of the MIME file can be selected for further analysis with option -s. Here is an example where we use the index 2 to select the second part:

emldump.py sample.vir -s 2
00000000: 20 20 20 0D 0A 20 20 20 41 20 63 6F 70 79 20 6F     ..   A copy o
00000010: 66 20 79 6F 75 72 20 41 44 50 20 54 6F 74 61 6C  f your ADP Total
00000020: 53 6F 75 72 63 65 20 50 61 79 72 6F 6C 6C 20 49  Source Payroll I
00000030: 6E 76 6F 69 63 65 20 66 6F 72 20 74 68 65 20 66  nvoice for the f
00000040: 6F 6C 6C 6F 77 69 6E 67 20 70 61 79 72 6F 6C 6C  ollowing payroll
...

When a part is selected, by default the content of the part is dumped in HEX/ASCII format (option -a). An hexdump can be obtained with option -x, like in this example:
 
emldump.py sample.vir -s 2 -x
20 20 20 0D 0A 20 20 20 41 20 63 6F 70 79 20 6F
66 20 79 6F 75 72 20 41 44 50 20 54 6F 74 61 6C
53 6F 75 72 63 65 20 50 61 79 72 6F 6C 6C 20 49
6E 76 6F 69 63 65 20 66 6F 72 20 74 68 65 20 66
6F 6C 6C 6F 77 69 6E 67 20 70 61 79 72 6F 6C 6C
20 69 73 09 20 20 20 69 73 20 61 74 74 61 63 68

The raw content of the part can be dumped too with option -d. This can be used to redirect to a file or piped into another analysis program.

Option -s (select) takes an index number, but can also take a MIME type, like in this example:
emldump.py sample.vir -s text/plain

emldump can scan the content of the parts with YARA rules (the YARA Python module must be installed). You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files. All parts are scanned with the provided YARA rules, you can not use option -s to select an individual part.

Content of example.eml:
emldump.py example.eml
1: M         multipart/mixed
2:        32 text/plain
3:    114704 application/octet-stream

YARA example:
emldump.py -y contains_pe_file.yara example.eml
3:    114704 application/octet-stream contains_pe_file.yara Contains_PE_File

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) inside MIME files. The rule triggered for part 3, because it contains an EXE file encoded in BASE64.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
emldump.py -y contains_pe_file.yara --yarastrings example.eml
3:    114704 application/octet-stream contains_pe_file.yara Contains_PE_File
 000010 $a 4d5a 'MZ'
 0004e4 $a 4d5a 'MZ'
 01189f $a 4d5a 'MZ'
 
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

maldoc.yara are YARA rules to detect shellcode, based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

When looking for traces of Windows executable code (PE files, shellcode, ...) with YARA rules, one must take into account the fact that the executable code might have been encoded (for example via XOR and a key) to evade detection.
To deal with this possibility, emldump supports decoders. A decoder is another type of plugin, that will bruteforce a type of encoding on each part. For example, decoder_xor1 will encode each part via XOR and a key of 1 byte. So effectively, 256 different encodings of the part will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
emldump.py -y contains_pe_file.yara -D decoder_xor1 example-xor.eml
3:    114704 application/octet-stream contains_pe_file.yara Contains_PE_File (XOR 1 byte key 0x14)

The YARA rule triggers on part 3. It contains a PE file encoded via XORing each byte with 0x14.

You can specify more than one decoder separated by a comma ,.
emldump.py -y contains_pe_file.yara -D decoder_xor1,decoder_rol1,decoder_add1 example-xor.eml
3:    114704 application/octet-stream contains_pe_file.yara Contains_PE_File (XOR 1 byte key 0x14)

Some decoders take options, to be provided with option --decoderoptions.

Use option --jsonoutput to produce JSON output for all the parts that are not multiparts. This output can be consumed by other tools like strings.py, file-magic.py, ...

Option -c (--cut) allows for the partial selection of a stream. Use this option to "cut out" part of the stream.
The --cut option takes an argument to specify which section of bytes to select from the stream. This argument is composed of 2 terms separated by a colon (:), like this:
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
This argument can be used to dump the first 256 bytes of a PE file located inside the stream: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the stream: [d0cf11e0]:
When this option is not used, the complete stream is selected. 

Option -E (extra) calculates extra information. This option takes a parameter describing the extra data that needs to be calculated and displayed for each part. The following variables are defined:
  %INDEX%: the index of the part
  %INDICATOR%: Multipart indicator
  %LENGTH%': the length of the part
  %TYPE%: the type of the part
  %MD5%: calculates MD5 hash
  %SHA1%: calculates SHA1 hash
  %SHA256%: calculates SHA256 hash
  %ENTROPY%: calculates entropy
  %HEADHEX%: display first 20 bytes of the part as hexadecimal
  %HEADASCII%: display first 20 bytes of the part as ASCII
  %TAILHEX%: display last 20 bytes of the part as hexadecimal
  %TAILASCII%: display last 20 bytes of the part as ASCII
  %HISTOGRAM%: calculates a histogram
                 this is the prevalence of each byte value (0x00 trough 0xFF)
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

The parameter for -E may contain other text than the variables, which will be printed. Escape characters \\n and \\t are supported.
Example displaying the MD5 and SHA256 hash per part, separated by a space character:
emldump.py -E "%MD5% %SHA256%" example.eml
1: M         multipart/mixed 
2:        32 text/plain  989a168dcc073b3365269f1173a8edb0 d181b815ced40f1bb5738483fec79cb11347c6f4212a45d917ad13ab5d386809
3:    114704 application/octet-stream  4a8ed6be91d63104f91626ef8db30fe3 1a15d8f44b6549c8b49d067e8793d38628348fffeaab17685d40e3dfa890e442

If the extra parameter starts with !, then it replaces the complete output line (in stead of being appended to the output line).
Example:
emldump.py -E "!%INDEX% %MD5%" example.eml
1
2 989a168dcc073b3365269f1173a8edb0
3 4a8ed6be91d63104f91626ef8db30fe3

To include extra data with each use of emldump, define environment variable EMLDUMP_EXTRA with the parameter that should be passed to -E. When environment variable EMLDUMP_EXTRA is defined, option -E can be ommited. When option -E is used together with environment variable EMLDUMP_EXTRA, the parameter of option -E is used and the environment variable is ignored.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 78))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

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

def IsNumeric(str):
    return re.match('^[0-9]+', str)

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
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % P23Ord(b)
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
        hexDump+= ' %02X' % P23Ord(b)
        asciiDump += IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

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

def ExtraInfoENTROPY(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%f' % entropy

def ExtraInfoHEADHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[:16]).decode()

def ExtraInfoHEADASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[:16]])

def ExtraInfoTAILHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[-16:]).decode()

def ExtraInfoTAILASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
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
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def GenerateExtraInfo(extra, index, indicator, type, stream):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
        prefix = ''
    else:
        prefix = ' '
    dExtras = {'%INDEX%': lambda x: '%d' % index,
               '%INDICATOR%': lambda x: indicator,
               '%LENGTH%': lambda x: IFF(stream == None, '', lambda: '%d' % len(stream)),
               '%TYPE%': lambda x: type,
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
    return prefix + extra.replace(r'\t', '\t').replace(r'\n', '\n')

def HeaderValueDecode(value):
    valueDecoded, valueType = email.header.decode_header(value)[0]
    if valueType != None:
        valueDecoded = valueDecoded.decode(valueType)
    if isinstance(valueDecoded, bytes):
        valueDecoded = repr(valueDecoded)
    return valueDecoded

def HeaderValueJWT(value):
    value = HeaderValueDecode(value).strip()
    result = value.split('.')
    if len(result) >= 2:
        jwtAlg = binascii.a2b_base64(result[0]).decode('latin')
        jwtToken = binascii.a2b_base64(result[1]).decode('latin')
        result = '%s %s' % (jwtAlg, jwtToken)
    else:
        result = '<ERROR>'
    return result

def GenerateExtraInfoHeaders(extra, key, value):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
        prefix = ''
    else:
        prefix = ' '
    dExtras = {'%INDEX%': lambda x: '%d' % index,
               '%INDICATOR%': lambda x: indicator,
               '%LENGTH%': lambda x: IFF(stream == None, '', lambda: '%d' % len(stream)),
               '%TYPE%': lambda x: type,
               '%MD5%': ExtraInfoMD5,
               '%SHA1%': ExtraInfoSHA1,
               '%SHA256%': ExtraInfoSHA256,
               '%ENTROPY%': ExtraInfoENTROPY,
               '%HEADHEX%': ExtraInfoHEADHEX,
               '%HEADASCII%': ExtraInfoHEADASCII,
               '%TAILHEX%': ExtraInfoTAILHEX,
               '%TAILASCII%': ExtraInfoTAILASCII,
               '%HISTOGRAM%': ExtraInfoHISTOGRAM,

               '%RAW%': lambda x: x,
               '%DECODE%': HeaderValueDecode,
               '%DECODESTRIP%': lambda x: HeaderValueDecode(x).strip(),
               '%JWT%': HeaderValueJWT,
              }
    for variable in dExtras:
        if variable in extra:
            extra = extra.replace(variable, dExtras[variable](value))
    return prefix + extra.replace(r'\t', '\t').replace(r'\n', '\n')

def ContainsField(line):
    for c in line:
        if c == ' ':
            return False
        if c >= '\x00' and c <= '\x1F':
            return False
        if c == ':':
            return True
    return False

def StartsWithWhitespace(line):
    if line == '':
        return False
    return line[0] in ' \t'

def PrintWarningSelection(select, selectionCounter):
    if select != '' and selectionCounter == 0:
        print('Warning: no part was selected with expression %s' % select)

def Deobfuscate(data):
    oMatch = re.search(b'mime +-version:(.+)', data, flags=re.I|re.S)
    if oMatch != None:
        return b'mime-version:' + oMatch.groups()[0]
    return data
    
class cMyJSONOutput():

    def __init__(self):
        self.items = []
        self.counter = 1

    def AddIdItem(self, id, name, data):
        self.items.append({'id': id, 'name': name, 'content': binascii.b2a_base64(data).strip(b'\n').decode()})

    def AddItem(self, name, data):
        self.AddIdItem(self.counter, name, data)
        self.counter += 1

    def GetJSON(self):
        return json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': self.items})

def EMLDump(emlfilename, options):
    FixPipe()
    if emlfilename == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        data = sys.stdin.buffer.read()
    elif emlfilename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(emlfilename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        data = oZipContent.read()
        oZipContent.close()
        oZipfile.close()
    else:
        data = File2String(emlfilename)

    if options.fix:
        data = Deobfuscate(data)

    data = data.decode(encoding='utf8', errors='ignore')

    global decoders
    decoders = []
    LoadDecoders(options.decoders, True)

    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)

    counter = 0
    for line in data.splitlines():
        if ContainsField(line):
            break
        counter += 1
    if not options.header and not options.filter and options.select == '' and counter != 0:
        if counter == 1:
            print('Warning: the first line does not contain a field.')
        else:
            print('Warning: the first %d lines do not contain a field.' % counter)

    if not options.filter and options.select == '':
#        for line in data.splitlines(True):
#            if len(line) > 100:
#                print('Warning: contains lines longer than 100 characters.')
#                break
        warningPrinted = False
        for line in data.splitlines(True):
            if line == '\r\n':
                break
            if not StartsWithWhitespace(line) and not ContainsField(line) and not warningPrinted:
                print('Warning: the first block contains lines that are not a field.')
                warningPrinted = True

    if options.header or options.filter:
        data = ''.join(data.splitlines(True)[counter:])

    if options.filter:
#        data = ''.join([line for line in data.splitlines(True) if len(line) <= 100])
        temp = []
        firstBlock = True
        for line in data.splitlines(True):
            if not firstBlock:
                temp.append(line)
            if firstBlock and (StartsWithWhitespace(line) or ContainsField(line)):
                temp.append(line)
            if firstBlock and line == '\r\n':
                firstBlock = False
                temp.append(line)
        data = ''.join(temp)

    oEML = email.message_from_string(data)

    if options.headers:
        for key, value in oEML.items():
            line = key
            if options.select == '' or options.select == key:
                extrainfo = GenerateExtraInfoHeaders(options.extra, key, value)
                if options.extra.startswith('!'):
                    line = ''
                line += extrainfo
            if options.select == '' or options.select == key:
                print(line)
    elif options.select == '':
        if options.yara == None and not options.jsonoutput:
            counter = 1
            for oPart in oEML.walk():
                data = oPart.get_payload(decode=True)
                if data == None:
                    lengthString = '       '
                else:
                    lengthString = '%7d' % len(data)
                extrainfo = GenerateExtraInfo(options.extra, counter, IFF(oPart.is_multipart(), 'M', ''), oPart.get_content_type(), data)
                fieldfilename = oPart.get_filename()
                if fieldfilename == None:
                    fieldfilename = ''
                else:
                    fieldfilename = ' (' + fieldfilename + ')'
                line = '%d: %s %s %s%s' % (counter, IFF(oPart.is_multipart(), 'M', ' '), lengthString, oPart.get_content_type(), fieldfilename)
                if options.extra.startswith('!'):
                    line = ''
                line += extrainfo
                print(line)
                counter += 1
        elif options.yara != None:
            counter = 1
            for oPart in oEML.walk():
                data = oPart.get_payload(decode=True)
                if data != None:
                    oDecoders = [cIdentity(data, None)]
                    for cDecoder in decoders:
                        try:
                            oDecoder = cDecoder(data, options.decoderoptions)
                            oDecoders.append(oDecoder)
                        except Exception as e:
                            print('Error instantiating decoder: %s' % cDecoder.name)
                            if options.verbose:
                                raise e
                            return
                    for oDecoder in oDecoders:
                        while oDecoder.Available():
                            for result in rules.match(data=oDecoder.Decode()):
                                lengthString = '%7d' % len(data)
                                decoderName = oDecoder.Name()
                                if decoderName != '':
                                    decoderName = ' (%s)' % decoderName
                                print('%d: %s %s %-20s %s %s%s' % (counter, IFF(oPart.is_multipart(), 'M', ' '), lengthString, oPart.get_content_type(), result.namespace, result.rule, decoderName))
                                if options.yarastrings:
                                    for stringdata in result.strings:
                                        print(' %06x %s %s %s' % (stringdata[0], stringdata[1], binascii.hexlify(stringdata[2]), repr(stringdata[2])))
                counter += 1
        elif options.jsonoutput:
            oMyJSONOutput = cMyJSONOutput()
            counter = 1
            for oPart in oEML.walk():
                data = oPart.get_payload(decode=True)
                if data == None:
                    data = b''
                if not oPart.is_multipart():
                    oMyJSONOutput.AddIdItem(counter, oPart.get_content_type(), data)
                counter += 1
            print(oMyJSONOutput.GetJSON())

    else:
        if options.dump:
            DumpFunction = lambda x:x
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        elif options.hexdump:
            DumpFunction = HexDump
        else:
            DumpFunction = HexAsciiDump
        counter = 1
        selectionCounter = 0
        for oPart in oEML.walk():
            if IsNumeric(options.select) and counter == int(options.select) or not IsNumeric(options.select) and oPart.get_content_type() == options.select:
                if not oPart.is_multipart():
                    StdoutWriteChunked(DumpFunction(CutData(oPart.get_payload(decode=True), options.cut)[0]))
                else:
                    print('Warning: you selected a multipart stream')
                selectionCounter += 1
                break
            counter += 1
        PrintWarningSelection(options.select, selectionCounter)

def OptionsEnvironmentVariables(options):
    if options.extra == '':
        options.extra = os.getenv('EMLDUMP_EXTRA', options.extra)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [mimefile]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='skip first lines without fields')
    oParser.add_option('-I', '--headers', action='store_true', default=False, help='Display headers')
    oParser.add_option('-s', '--select', default='', help='select item nr or MIME type for dumping')
    oParser.add_option('-y', '--yara', help="YARA rule file (or directory or @file) to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: EMLDUMP_EXTRA)')
    oParser.add_option('-f', '--filter', action='store_true', default=False, help='filter out obfuscating lines')
    oParser.add_option('-F', '--fix', action='store_true', default=False, help='Fix obfuscated lines')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
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
    elif len(args) == 1:
        EMLDump(args[0], options)
    else:
        EMLDump('', options)

if __name__ == '__main__':
    Main()
