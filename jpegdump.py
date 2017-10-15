#!/usr/bin/env python

__description__ = 'JPEG file analysis tool'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2017/09/19'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/09/09: start
  2017/09/10: continue
  2017/09/12: 0.0.2 reporting missing bytes
  2017/09/19: 0.0.3 refactoring; added option -f

Todo:
"""

import optparse
import sys
import os
import zipfile
import binascii
import random
import gzip
import collections
import glob
import textwrap
import re
import struct
import string
import math
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO

def PrintManual():
    manual = '''
Manual:

TBD
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

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

def LoremIpsumSentence(minimum, maximum):
    words = ['lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'etiam', 'tortor', 'metus', 'cursus', 'sed', 'sollicitudin', 'ac', 'sagittis', 'eget', 'massa', 'praesent', 'sem', 'fermentum', 'dignissim', 'in', 'vel', 'augue', 'scelerisque', 'auctor', 'libero', 'nam', 'a', 'gravida', 'odio', 'duis', 'vestibulum', 'vulputate', 'quam', 'nec', 'cras', 'nibh', 'feugiat', 'ut', 'vitae', 'ornare', 'justo', 'orci', 'varius', 'natoque', 'penatibus', 'et', 'magnis', 'dis', 'parturient', 'montes', 'nascetur', 'ridiculus', 'mus', 'curabitur', 'nisl', 'egestas', 'urna', 'iaculis', 'lectus', 'maecenas', 'ultrices', 'velit', 'eu', 'porta', 'hac', 'habitasse', 'platea', 'dictumst', 'integer', 'id', 'commodo', 'mauris', 'interdum', 'malesuada', 'fames', 'ante', 'primis', 'faucibus', 'accumsan', 'pharetra', 'aliquam', 'nunc', 'at', 'est', 'non', 'leo', 'nulla', 'sodales', 'porttitor', 'facilisis', 'aenean', 'condimentum', 'rutrum', 'facilisi', 'tincidunt', 'laoreet', 'ultricies', 'neque', 'diam', 'euismod', 'consequat', 'tempor', 'elementum', 'lobortis', 'erat', 'ligula', 'risus', 'donec', 'phasellus', 'quisque', 'vivamus', 'pellentesque', 'tristique', 'venenatis', 'purus', 'mi', 'dictum', 'posuere', 'fringilla', 'quis', 'magna', 'pretium', 'felis', 'pulvinar', 'lacinia', 'proin', 'viverra', 'lacus', 'suscipit', 'aliquet', 'dui', 'molestie', 'dapibus', 'mollis', 'suspendisse', 'sapien', 'blandit', 'morbi', 'tellus', 'enim', 'maximus', 'semper', 'arcu', 'bibendum', 'convallis', 'hendrerit', 'imperdiet', 'finibus', 'fusce', 'congue', 'ullamcorper', 'placerat', 'nullam', 'eros', 'habitant', 'senectus', 'netus', 'turpis', 'luctus', 'volutpat', 'rhoncus', 'mattis', 'nisi', 'ex', 'tempus', 'eleifend', 'vehicula', 'class', 'aptent', 'taciti', 'sociosqu', 'ad', 'litora', 'torquent', 'per', 'conubia', 'nostra', 'inceptos', 'himenaeos']
    sample = random.sample(words, random.randint(minimum, maximum))
    sample[0] = sample[0].capitalize()
    return ' '.join(sample) + '.'

def LoremIpsum(sentences):
    return ' '.join([LoremIpsumSentence(15, 30) for i in range(sentences)])

STATE_START = 0
STATE_IDENTIFIER = 1
STATE_STRING = 2
STATE_SPECIAL_CHAR = 3
STATE_ERROR = 4

def Tokenize(expression):
    result = []
    token = ''
    state = STATE_START
    while expression != '':
        char = expression[0]
        expression = expression[1:]
        if char == "'":
            if state == STATE_START:
                state = STATE_STRING
            elif state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                state = STATE_STRING
                token = ''
            elif state == STATE_STRING:
                result.append([STATE_STRING, token])
                state = STATE_START
                token = ''
        elif char >= '0' and char <= '9' or char.lower() >= 'a' and char.lower() <= 'z':
            if state == STATE_START:
                token = char
                state = STATE_IDENTIFIER
            else:
                token += char
        elif char == ' ':
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ''
                state = STATE_START
            elif state == STATE_STRING:
                token += char
        else:
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ''
                state = STATE_START
                result.append([STATE_SPECIAL_CHAR, char])
            elif state == STATE_STRING:
                token += char
            else:
                result.append([STATE_SPECIAL_CHAR, char])
                token = ''
    if state == STATE_IDENTIFIER:
        result.append([state, token])
    elif state == STATE_STRING:
        result = [[STATE_ERROR, 'Error: string not closed', token]]
    return result

def ParseFunction(tokens):
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    if tokens[0][0] != STATE_IDENTIFIER:
        print('Parsing error')
        return None, tokens
    function = tokens[0][1]
    tokens = tokens[1:]
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != '(':
        print('Parsing error')
        return None, tokens
    tokens = tokens[1:]
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    arguments = []
    while True:
        if tokens[0][0] != STATE_IDENTIFIER and tokens[0][0] != STATE_STRING:
            print('Parsing error')
            return None, tokens
        arguments.append(tokens[0])
        tokens = tokens[1:]
        if len(tokens) == 0:
            print('Parsing error')
            return None, tokens
        if tokens[0][0] != STATE_SPECIAL_CHAR or (tokens[0][1] != ',' and tokens[0][1] != ')'):
            print('Parsing error')
            return None, tokens
        if tokens[0][0] == STATE_SPECIAL_CHAR and tokens[0][1] == ')':
            tokens = tokens[1:]
            break
        tokens = tokens[1:]
        if len(tokens) == 0:
            print('Parsing error')
            return None, tokens
    return [[function, arguments], tokens]

def Parse(expression):
    tokens = Tokenize(expression)
    if len(tokens) == 0:
        print('Parsing error')
        return None
    if tokens[0][0] == STATE_ERROR:
        print(tokens[0][1])
        print(tokens[0][2])
        print(expression)
        return None
    functioncalls = []
    while True:
        functioncall, tokens = ParseFunction(tokens)
        if functioncall == None:
            return None
        functioncalls.append(functioncall)
        if len(tokens) == 0:
            return functioncalls
        if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != '+':
            print('Parsing error')
            return None
        tokens = tokens[1:]

def InterpretInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    try:
        return int(token[1])
    except:
        return None

def Hex2Bytes(hexadecimal):
    if len(hexadecimal) % 2 == 1:
        hexadecimal = '0' + hexadecimal
    try:
        return binascii.a2b_hex(hexadecimal)
    except:
        return None

def InterpretHexInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith('0x'):
        return None
    bytes = Hex2Bytes(token[1][2:])
    if bytes == None:
        return None
    integer = 0
    for byte in bytes:
        integer = integer * 0x100 + C2IIP2(byte)
    return integer

def InterpretNumber(token):
    number = InterpretInteger(token)
    if number == None:
        return InterpretHexInteger(token)
    else:
        return number

def InterpretBytes(token):
    if token[0] == STATE_STRING:
        return token[1]
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith('0x'):
        return None
    return Hex2Bytes(token[1][2:])

def CheckFunction(functionname, arguments, countarguments, maxcountarguments=None):
    if maxcountarguments == None:
        if countarguments == 0 and len(arguments) != 0:
            print('Error: function %s takes no arguments, %d are given' % (functionname, len(arguments)))
            return True
        if countarguments == 1 and len(arguments) != 1:
            print('Error: function %s takes 1 argument, %d are given' % (functionname, len(arguments)))
            return True
        if countarguments != len(arguments):
            print('Error: function %s takes %d arguments, %d are given' % (functionname, countarguments, len(arguments)))
            return True
    else:
        if len(arguments) < countarguments or len(arguments) > maxcountarguments:
            print('Error: function %s takes between %d and %d arguments, %d are given' % (functionname, countarguments, maxcountarguments, len(arguments)))
            return True
    return False

def CheckNumber(argument, minimum=None, maximum=None):
    number = InterpretNumber(argument)
    if number == None:
        print('Error: argument should be a number: %s' % argument[1])
        return None
    if minimum != None and number < minimum:
        print('Error: argument should be minimum %d: %d' % (minimum, number))
        return None
    if maximum != None and number > maximum:
        print('Error: argument should be maximum %d: %d' % (maximum, number))
        return None
    return number

FUNCTIONNAME_REPEAT = 'repeat'
FUNCTIONNAME_RANDOM = 'random'
FUNCTIONNAME_CHR = 'chr'
FUNCTIONNAME_LOREMIPSUM = 'loremipsum'

def Interpret(expression):
    functioncalls = Parse(expression)
    if functioncalls == None:
        return None
    decoded = ''
    for functioncall in functioncalls:
        functionname, arguments = functioncall
        if functionname == FUNCTIONNAME_REPEAT:
            if CheckFunction(functionname, arguments, 2):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            bytes = InterpretBytes(arguments[1])
            if bytes == None:
                print('Error: argument should be a byte sequence: %s' % arguments[1][1])
                return None
            decoded += number * bytes
        elif functionname == FUNCTIONNAME_RANDOM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            decoded += ''.join([chr(random.randint(0, 255)) for x in range(number)])
        elif functionname == FUNCTIONNAME_LOREMIPSUM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            decoded += LoremIpsum(number)
        elif functionname == FUNCTIONNAME_CHR:
            if CheckFunction(functionname, arguments, 1, 2):
                return None
            number = CheckNumber(arguments[0], minimum=1, maximum=255)
            if number == None:
                return None
            if len(arguments) == 1:
                decoded += chr(number)
            else:
                number2 = CheckNumber(arguments[1], minimum=1, maximum=255)
                if number2 == None:
                    return None
                decoded += ''.join([chr(n) for n in range(number, number2 + 1)])
        else:
            print('Error: unknown function: %s' % functionname)
            return None
    return decoded

def FilenameCheckHash(filename):
    if filename.startswith('#h#'):
        return Hex2Bytes(filename[3:])
    elif filename.startswith('#b#'):
        try:
            return binascii.a2b_base64(filename[3:])
        except:
            return None
    elif filename.startswith('#e#'):
        return Interpret(filename[3:])
    elif filename.startswith('#'):
        return filename[1:]
    else:
        return ''

class cBinaryFile:
    def __init__(self, filename, zippassword='infected', noextraction=False, literalfilename=False):
        self.filename = filename
        self.zippassword = zippassword
        self.noextraction = noextraction
        self.literalfilename = literalfilename
        self.oZipfile = None

        if self.literalfilename:
            decoded = ''
        else:
            decoded = FilenameCheckHash(self.filename)
            if decoded == None:
                raise Exception('Error parsing filename: ' + self.filename)

        if self.filename == '':
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            self.fIn = sys.stdin
        elif decoded != '':
            self.fIn = StringIO(decoded)
        elif not self.noextraction and self.filename.lower().endswith('.zip'):
            self.oZipfile = zipfile.ZipFile(self.filename, 'r')
            if len(self.oZipfile.infolist()) == 1:
                self.fIn = self.oZipfile.open(self.oZipfile.infolist()[0], 'r', self.zippassword)
            else:
                self.oZipfile.close()
                self.oZipfile = None
                self.fIn = open(self.filename, 'rb')
        elif not self.noextraction and self.filename.lower().endswith('.gz'):
            self.fIn = gzip.GzipFile(self.filename, 'rb')
        else:
            self.fIn = open(self.filename, 'rb')

    def close(self):
        if self.fIn != sys.stdin:
            self.fIn.close()
        if self.oZipfile != None:
            self.oZipfile.close()

    def Data(self):
        data = self.fIn.read()
        self.close()
        return data

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
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

def Glob(filename):
    filenames = glob.glob(filename)
    if len(filenames) == 0:
        return [filename]
    else:
        return filenames

def ExpandFilenameArguments(filenames, literalfilenames=False):
    if len(filenames) == 0:
        return [['', '']]
    elif literalfilenames:
        return [[filename, ''] for filename in filenames]
    else:
        cutexpression = ''
        result = []
        for filename in list(collections.OrderedDict.fromkeys(sum(map(Glob, sum(map(ProcessAt, filenames), [])), []))):
            if filename.startswith('#c#'):
                cutexpression = filename[3:]
            else:
                result.append([filename, cutexpression])
        if result == []:
            return [['', cutexpression]]
        return result

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
            hexDump += IFF(hexDump == '', '', ' ') + '%02X' % C2IIP2(b)
        oDumpStream.Addline(hexDump)
        return oDumpStream.Content()

    def CombineHexAscii(self, hexDump, asciiDump):
        if hexDump == '':
            return ''
        return hexDump + '  ' + (' ' * (3 * (self.dumplinelength - len(asciiDump)))) + asciiDump

    def HexAsciiDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        asciiDump = ''
        for i, b in enumerate(self.data):
            b = C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
                hexDump = '%08X:' % (i + self.offset)
                asciiDump = ''
            hexDump+= ' %02X' % b
            asciiDump += IFF(b >= 32 and b <= 128, chr(b), '.')
        oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
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

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

def Print(line, options=None):
    if options == None or options.select == '':
        print(line)

def CalculateByteStatistics(dPrevalence=None, data=None):
    averageConsecutiveByteDifference = None
    if dPrevalence == None:
        dPrevalence = {iter: 0 for iter in range(0x100)}
        sumDifferences = 0.0
        previous = None
        if len(data) > 1:
            for byte in data:
                byte = C2IIP2(byte)
                dPrevalence[byte] += 1
                if previous != None:
                    sumDifferences += abs(byte - previous)
                previous = byte
            averageConsecutiveByteDifference = sumDifferences /float(len(data)-1)
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
    countHexadecimalBytes = 0
    countBASE64Bytes = 0
    for iter in range(0x30, 0x3A):
        countHexadecimalBytes += dPrevalence[iter]
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x41, 0x47):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x61, 0x67):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x41, 0x5B):
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x61, 0x7B):
        countBASE64Bytes += dPrevalence[iter]
    countBASE64Bytes += dPrevalence[ord('+')] + dPrevalence[ord('/')] + dPrevalence[ord('=')]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
            countUniqueBytes += 1
    return sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes, countHexadecimalBytes, countBASE64Bytes, averageConsecutiveByteDifference

def GetMarkerName(markerType):
    dMarkers = {0xD8:'SOI', 0xD9:'EOI', 0xDA:'SOS', 0xDB:'DQT', 0xC0:'SOF0', 0xC2:'SOF2', 0xC4:'DHT', 0xDD:'DRI', 0xFE:'COM'}
    if markerType in dMarkers:
        return dMarkers[markerType]
    if markerType >= 0xE0 and markerType <= 0xEF:
        return 'APP%d' % (markerType & 0x0F)
    if markerType >= 0xD0 and markerType <= 0xD7:
        return 'RST%d' % (markerType & 0x0F)
    return ''

def ConvertNone(value, replacement=''):
    if value == None:
        return replacement
    else:
        return value

def ProcessJPEGFileSub(data, options, startposition=0):
    counter = 1
    position = startposition
    ff00Counter = 0
    ffdaFlag = False
    endOfPrevious = startposition
    while True:
        found = data.find(C2BIP3('\xFF'), position)
        if found == -1:
            break
        marker = data[found:found+4]
        markerType = struct.unpack('xB', marker[0:2])[0]
        markerName = GetMarkerName(markerType)
        if markerType == 0x00:
            if ffdaFlag:
                ff00Counter += 1
            position = found + 1
        elif ffdaFlag and markerType >= 0xD0 and markerType <= 0xD7:
            Print('    p=0x%08x    : m=%02x%02x %s' % (found, struct.unpack('Bx', marker[0:2])[0], markerType, markerName), options)
            position = found + 1
        else:
            if ffdaFlag:
                stats = CalculateByteStatistics(data=data[endOfPrevious:found])
                Print('                                  entropy-coded data: l=%d e=%f a=%f #ff00=%d' % ((found - endOfPrevious), stats[1], ConvertNone(stats[10], 0.0), ff00Counter), options)
                ff00Counter = 0
                if options.select == '%dd' % (counter - 1):
                    if options.dump:
                        IfWIN32SetBinary(sys.stdout)
                        StdoutWriteChunked(data[endOfPrevious:found])
                    elif options.unstuffeddump:
                        IfWIN32SetBinary(sys.stdout)
                        StdoutWriteChunked(data[endOfPrevious:found].replace(C2BIP3('\xFF\x00'), C2BIP3('\xFF')))
                    elif options.hexdump:
                        Print(cDump(data[endOfPrevious:found], '      ', endOfPrevious).HexDump()[:-1])
                    else:
                        Print(cDump(data[endOfPrevious:found], '      ', endOfPrevious).HexAsciiDump()[:-1])
                endOfPrevious = found
            if markerType == 0xda:
                ffdaFlag = True
            else:
                ffdaFlag = False
            if markerType >= 0xD0 and markerType <= 0xD9:
                Print('%3d p=0x%08x d=%d: m=%02x%02x %s' % (counter, found, found - endOfPrevious, struct.unpack('Bx', marker[0:2])[0], markerType, markerName), options)
                position = found + 2
                endOfPrevious = position
                counter += 1
            else:
                size = struct.unpack('>xxH', marker)[0]
                stats = CalculateByteStatistics(data=data[found+4:found+2+size])
                line = '%3d p=0x%08x d=%d: m=%02x%02x %-5s l=%5d e=%f a=%f' % (counter, found, found - endOfPrevious, struct.unpack('Bx', marker[0:2])[0], markerType, markerName, size, stats[1], ConvertNone(stats[10], 0.0))
                if markerType == 0xDB:
                    line += ' remark: %d/65 = %f' % (size - 2, (size - 2.0) / 65.0)
                if markerType == 0xC0 and len(data[found+4:found+2+size]) >= 6:
                    info = struct.unpack('>BHHB', data[found+4:found+2+size][:6])
                    line += ' remark: p=%d h=%d w=%d c=%d' % info
                Print(line, options)
                if options.select == str(counter):
                    if options.dump:
                        IfWIN32SetBinary(sys.stdout)
                        StdoutWriteChunked(data[found+4:found+2+size])
                    elif options.hexdump:
                        Print(cDump(data[found+4:found+2+size], '', found + 4).HexDump()[:-1])
                    else:
                        Print(cDump(data[found+4:found+2+size], '', found + 4).HexAsciiDump()[:-1])
                position = found + 2 + size
                endOfPrevious = position
                counter += 1
        if options.findsoi and markerName == '' and markerType != 0x00:
            return
    trailing = len(data) - position
    if trailing > 0:
        stats = CalculateByteStatistics(data=data[position:])
        Print('%3d p=0x%08x    : *trailing*  l=%5d e=%f' % (counter, position, len(data) - position, stats[1]), options)
        if options.select == str(counter):
            if options.dump:
                IfWIN32SetBinary(sys.stdout)
                StdoutWriteChunked(data[position:])
            elif options.hexdump:
                Print(cDump(data[position:], '', position).HexDump()[:-1])
            else:
                Print(cDump(data[position:], '', position).HexAsciiDump()[:-1])
    elif trailing < 0:
        Print('                                   *warning* %d byte(s) missing' % -trailing, options)

def ProcessJPEGFile(filename, cutexpression, options):
    data = CutData(cBinaryFile(filename, C2BIP3(options.password), options.noextraction, options.literalfilenames).Data(), cutexpression)
    Print('File: %s' % filename, options)
    if options.findsoi:
        position = 0
        while True:
            found = data.find(C2BIP3('\xFF\xD8'), position)
            if found == -1:
                break
            Print('Found SOI:', options)
            ProcessJPEGFileSub(data, options, found)
            position = found + 1
    else:
        ProcessJPEGFileSub(data, options)

def ProcessJPEGFiles(filenames, options):
    for filename, cutexpression in filenames:
        ProcessJPEGFile(filename, cutexpression, options)

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('-s', '--select', default='', help='Select marker nr for dumping')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='Perform dump')
    oParser.add_option('-u', '--unstuffeddump', action='store_true', default=False, help='Perform unstuffed dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='Perform HEX/ASCII dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='Perform HEX dump')
    oParser.add_option('-f', '--findsoi', action='store_true', default=False, help='Find SOI markers')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    ProcessJPEGFiles(ExpandFilenameArguments(args, options.literalfilenames), options)

if __name__ == '__main__':
    Main()
