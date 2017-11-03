#!/usr/bin/env python

__description__ = 'Cut a section of bytes out of a file'
__author__ = 'Didier Stevens'
__version__ = '0.0.6'
__date__ = '2017/11/01'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/09/13: start
  2015/11/10: 0.0.2 added support for :-number
  2015/12/16: 0.0.3 added support [...]number+number
  2015/12/17: continue
  2016/08/02: 0.0.4 added dumps
  2017/03/04: 0.0.5 updated man
  2017/11/01: 0.0.6 updated cDump, added cBinaryFile

Todo:
"""

import optparse
import textwrap
import re
import cStringIO
import sys
import os
import zipfile
import binascii
import random
import gzip
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO

MALWARE_PASSWORD = 'infected'
dumplinelength = 16

def PrintManual():
    manual = '''
Manual:

cut-bytes.py reads a file (from disk, from stdin or from inside a (password protected) ZIP file) or a here document (#), and outputs it (partially) to stdout.
cut-bytes.py can be instructed via a cut-expression to only send partial input to stdout.

The cut-expression allows for the partial selection of a stream. Use this expression to "cut out" part of the stream.
This cut-expression is composed of 2 terms separated by a colon (:), like this:
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
This cut-expression can be used to dump the first 256 bytes of a PE file located inside the stream: ['MZ']:0x100l
This cut-expression can be used to dump the OLE file located inside the stream: [d0cf11e0]:

By default the output uses the same representation as the input, but this can be changed to hex, ascii dump or base64 with options -x, -X, -a, -b and -B.

In stead of cutting from a file, the file argument can be a here document. To achieve this, precede the text with character #.
If the text to pass via the argument contains control characters or non-printable characters, hexadecimal (#h#) or base64 (#b#) can be used.

Example:
 cut-bytes.py : #Hello
Output:
 Hello

Example:
 cut-bytes.py : #h#48656C6C6F
Output:
 Hello

Example:
 cut-bytes.py : #b#SGVsbG8=
Output:
 Hello

To process a file that starts with #, prefix it with a relative path to the current directory:
 cut-bytes.py : .\#data
Output:
 Test!

Or use option --literalfilenames.

cut-bytes can process a file stored inside a (password protected) ZIP file too. To process the ZIP file itself, use option --noextraction. The default password is infected, and can be changed with option --password.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

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

    def HexAsciiDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        asciiDump = ''
        for i, b in enumerate(self.data):
            b = self.C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
                hexDump = '%08X:' % (i + self.offset)
                asciiDump = ''
            if i % self.dumplinelength == self.dumplinelength / 2:
                hexDump += ' '
            hexDump += ' %02X' % b
            asciiDump += IFF(b >= 32 and b <= 128, chr(b), '.')
        oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
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

def HexAsciiDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump()

def Base64Dump(data, nowhitespace=False):
    return cDump(data, dumplinelength=dumplinelength).Base64Dump(nowhitespace=nowhitespace)

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

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

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

def CutBytes(expression, filename, options):
    if options.hexdump:
        DumpFunction = HexDump
    elif options.hexdumpnows:
        DumpFunction = lambda x: binascii.b2a_hex(x)
    elif options.base64:
        DumpFunction = Base64Dump
    elif options.base64nows:
        DumpFunction = lambda x: Base64Dump(x, True)
    elif options.asciidump:
        DumpFunction = HexAsciiDump
    else:
        DumpFunction = lambda x: x
        IfWIN32SetBinary(sys.stdout)

    StdoutWriteChunked(DumpFunction(CutData(cBinaryFile(filename, C2BIP3(options.password), options.noextraction, options.literalfilenames).Data(), expression)))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] cut-expression [[#]file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-X', '--hexdumpnows', action='store_true', default=False, help='perform hex dump without whitespace')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-b', '--base64', action='store_true', default=False, help='perform BASE64 dump')
    oParser.add_option('-B', '--base64nows', action='store_true', default=False, help='perform BASE64 dump without whitespace')
    oParser.add_option('--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0 or len(args) > 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return

    if ParseCutArgument(args[0])[0] == None:
        print('Error: the cut-expression is invalid: %s' % args[0])
        return

    if len(args) == 1:
        CutBytes(args[0], '', options)
    else:
        CutBytes(args[0], args[1], options)

if __name__ == '__main__':
    Main()
