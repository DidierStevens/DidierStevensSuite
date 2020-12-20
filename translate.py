#!/usr/bin/env python

__description__ = 'Translate bytes according to a Python expression'
__author__ = 'Didier Stevens'
__version__ = '2.5.11'
__date__ = '2020/12/20'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

No input validation (neither output) is performed by this program: it contains injection vulnerabilities

Developed with Python 2.7, tested with 2.7 and 3.3

History:
  2007/08/20: start
  2014/02/24: rewrite
  2014/02/27: manual
  2015/11/04: added option -f
  2015/11/05: continue
  2016/02/20: added option -r
  2016/04/25: 2.3.0 added StdoutWriteChunked() and option -R
  2016/09/07: 2.3.1 added option -e
  2016/09/09: continue
  2016/09/13: man
  2017/02/10: 2.4.0 added input filename # support
  2017/02/26: fixed Python 3 str vs bytes bug
  2017/06/04: 2.5.0 added #e# support
  2017/06/16: continued #e# support
  2017/07/29: added -2 option
  2017/08/09: 2.5.1 #e# chr can take a second argument
  2017/09/09: added functions Sani1 and Sani2 to help with input/output sanitization
  2018/01/29: 2.5.2 added functions GzipD and ZlibD; and fixed stdin/stdout for Python 3
  2018/02/12: 2.5.3 when the Python expression returns None (in stead of a byte value), no byte is written to output.
  2018/03/05: 2.5.4 updated #e# expressions
  2018/04/27: added option literalfilenames
  2019/02/20: 2.5.5 added ZlibRawD
  2019/02/26: 2.5.6 updated help
  2020/01/06: 2.5.7 added Xor function
  2020/06/08: 2.5.8 Python 3 fix
  2020/10/17: 2.5.9 Python 3 fix
  2020/11/04: 2.5.10 Python 3 fix
  2020/12/08: 2.5.11 Bug fix
  2020/12/20: added shl and shr

Todo:
"""

import optparse
import sys
import os
import textwrap
import re
import math
import binascii
import random
import zlib
import gzip
try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

def PrintManual():
    manual = '''
Manual:

Translate.py is a Python script to perform bitwise operations on files (like XOR, ROL/ROR, ...). You specify the bitwise operation to perform as a Python expression, and pass it as a command-line argument.

translate.py malware -o malware.decoded "byte ^ 0x10"
This will read file malware, perform XOR 0x10 on each byte (this is, expressed in Python: byte ^ 0x10), and write the result to file malware.decoded.

byte is a variable containing the current byte from the input file. Your expression has to evaluate to the modified byte. When your expression evaluates to None, no byte will be written to output. This can be used to delete bytes from the input.

For complex manipulation, you can define your own functions in a script file and load this with translate.py, like this:

translate.py malware -o malware.decoded "Process(byte)" process.py
process.py must contain the definition of function Process. Function Process must return the modified byte.

Another variable is also available: position. This variable contains the position of the current byte in the input file, starting from 0.

If only part of the file has to be manipulated, while leaving the rest unchanged, you can do it like this:

    def Process(byte):
        if position >= 0x10 and position < 0x20:
            return byte ^ 0x10
        else:
            return byte

This example will perform an XOR 0x10 operation from the 17th byte till the 32nd byte included. All other bytes remain unchanged.

Because Python has built-in shift operators (<< and >>) but no rotate operators, I've defined 2 rotate functions that operate on a byte: rol (rotate left) and ror (rotate right). They accept 2 arguments: the byte to rotate and the number of bit positions to rotate. For example, rol(0x01, 2) gives 0x04.

translate.py malware -o malware.decoded "rol(byte, 2)"

Another function I defined is IFF (the IF Function): IFF(expression, valueTrue, valueFalse). This function allows you to write conditional code without an if statement. When expression evaluates to True, IFF returns valueTrue, otherwise it returns valueFalse.

And yet 2 other functions I defined are Sani1 and Sani2. They can help you with input/output sanitization: Sani1 accepts a byte as input and returns the same byte, except if it is a control character. All control characters (except VT, LF and CR) are replaced by a space character (0x20). Sani2 is like Sani1, but sanitizes even more bytes: it sanitizes control characters like Sani1, and also all bytes equal to 0x80 and higher.

translate.py malware -o malware.decoded "IFF(position >= 0x10 and position < 0x20, byte ^ 0x10, byte)"

By default this program translates individual bytes via the provided Python expression. With option -f (fullread), translate.py reads the input file as one byte sequence and passes it to the function specified by the expression. This function needs to take one string as an argument and return one string (the translated file).

Option -r (regex) uses a regular expression to search through the file and then calls the provided function with a match argument for each matched string. The return value of the function (a string) is used to replace the matched string.
Option -R (filterregex) is similar to option -r (regex), except that it does not operate on the complete file, but on the file filtered for the regex.

Here are 2 examples with a regex. The input file (test-ah.txt) contains the following: 1234&H41&H42&H43&H444321

The first command will search for strings &Hxx and replace them with the character represented in ASCII by hexadecimal number xx:
translate.py -r "&H(..)" test-ah.txt "lambda m: chr(int(m.groups()[0], 16))"
Output: 1234ABCD4321

The second command is exactly the same as the first command, except that it uses option -R in stead or -r:
translate.py -R "&H(..)" test-ah.txt "lambda m: chr(int(m.groups()[0], 16))"
Output: ABCD

Option -e (execute) is used to execute Python commands before the command is executed. This can, for example, be used to import modules.
Here is an example to decompress a Flash file (.swf):
 translate.py -f -e "import zlib" sample.swf "lambda b: zlib.decompress(b[8:])"

You can use build-in function ZlibD too, and ZlibRawD for inflating without header, and GzipD for gzip decompression.

Build-in function Xor can be used for Xor decoding with a multi-byte key, like in this example:

Example:
 translate.py -f #h#320700130717 "lambda data: Xor(data, b'abc')"
Output:
 Secret

A second file can be used as input with option -2. The value of the current byte of the second input file is stored in variable byte2 (this too advances byte per byte together with the primary input file).

Example:
 translate.py -2 #021230 #Scbpbt "byte + byte2 - 0x30"
Output:
 Secret

In stead of using an input filename, the content can also be passed in the argument. To achieve this, prefix the text with character #.
If the text to pass via the argument contains control characters or non-printable characters, hexadecimal (#h#) or base64 (#b#) can be used.

Example:
 translate.py #h#89B5B4AEFDB4AEFDBCFDAEB8BEAFB8A9FC "byte ^0xDD"
Output:
 This is a secret!

File arguments that start with #e# are a notational convention to use expressions to generate data. An expression is a single function/string or the concatenation of several functions/strings (using character + as concatenation operator).
Strings can be characters enclosed by single quotes ('example') or hexadecimal strings prefixed by 0x (0xBEEF).
4 functions are available: random, loremipsum, repeat and chr.

Function random takes exactly one argument: an integer (with value 1 or more). Integers can be specified using decimal notation or hexadecimal notation (prefix 0x).
The random function generates a sequence of bytes with a random value (between 0 and 255), the argument specifies how many bytes need to be generated. Remark that the random number generator that is used is just the Python random number generator, not a cryptographic random number generator.

Example:

tool.py #e#random(100)

will make the tool process data consisting of a sequence of 100 random bytes.

Function loremipsum takes exactly one argument: an integer (with value 1 or more).
The loremipsum function generates "lorem ipsum" text (fake latin), the argument specifies the number of sentences to generate.

Example: #e#loremipsum(2) generates this text:
Ipsum commodo proin pulvinar hac vel nunc dignissim neque eget odio erat magna lorem urna cursus fusce facilisis porttitor congue eleifend taciti. Turpis duis suscipit facilisi tristique dictum praesent natoque sem mi egestas venenatis per dui sit sodales est condimentum habitasse ipsum phasellus non bibendum hendrerit.

Function chr takes one argument or two arguments.
chr with one argument takes an integer between 0 and 255, and generates a single byte with the value specified by the integer.
chr with two arguments takes two integers between 0 and 255, and generates a byte sequence with the values specified by the integers.
For example #e#chr(0x41,0x45) generates data ABCDE.

Function repeat takes two arguments: an integer (with value 1 or more) and a byte sequence. This byte sequence can be a quoted string of characters (single quotes), like 'ABCDE' or an hexadecimal string prefixed with 0x, like 0x4142434445.
The repeat function will create a sequence of bytes consisting of the provided byte sequence (the second argument) repeated as many times as specified by the first argument.
For example, #e#repeat(3, 'AB') generates byte sequence ABABAB.

When more than one function needs to be used, the byte sequences generated by the functions can be concatenated with the + operator.
For example, #e#repeat(10,0xFF)+random(100) will generate a byte sequence of 10 FF bytes followed by 100 random bytes.

To prevent the tool from processing file arguments with wildcard characters or special initial characters (@ and #) differently, but to process them as normal files, use option --literalfilenames.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def rol(byte, count):
    return (byte << count | byte >> (8- count)) & 0xFF

def ror(byte, count):
    return (byte >> count | byte << (8- count)) & 0xFF

def shl(bytes, count):
    return (int.from_bytes(bytes, byteorder='big') << count).to_bytes(len(bytes) + 1, 'big')

def shr(bytes, count):
    return (int.from_bytes(bytes, byteorder='big') >> count).to_bytes(len(bytes) + 1, 'big')

#Sanitize 1: Sanitize input: return space (0x20) for all control characters, except HT, LF and CR
def Sani1(byte):
    if byte in [0x09, 0x0A, 0x0D]:
        return byte
    if byte < 0x20:
        return 0x20
    return byte

#Sanitize 2: Sanitize input: return space (0x20) for all bytes equal to 0x80 and higher, and all control characters, except HT, LF and CR
def Sani2(byte):
    if byte in [0x09, 0x0A, 0x0D]:
        return byte
    if byte < 0x20:
        return 0x20
    if byte >= 0x80:
        return 0x20
    return byte

def GzipD(data):
    return gzip.GzipFile('', 'r', fileobj=StringIO(data)).read()

def ZlibD(data):
    return zlib.decompress(data)

def ZlibRawD(data):
    return zlib.decompress(data, -8)

def Xor(data, key):
    if sys.version_info[0] > 2:
        return bytes([byte ^ key[index % len(key)] for index, byte in enumerate(data)])
    else:
        return ''.join([chr(ord(char) ^ ord(key[index % len(key)])) for index, char in enumerate(data)])

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

#Convert String To Bytes If Python 3
def CS2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def Output(fOut, data):
    if fOut != sys.stdout:
        fOut.write(data)
    else:
        StdoutWriteChunked(data)

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

FUNCTIONNAME_REPEAT = 'repeat'
FUNCTIONNAME_RANDOM = 'random'
FUNCTIONNAME_CHR = 'chr'
FUNCTIONNAME_LOREMIPSUM = 'loremipsum'

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
    if tokens[0][0] == STATE_STRING or tokens[0][0] == STATE_IDENTIFIER and tokens[0][1].startswith('0x'):
        return [[FUNCTIONNAME_REPEAT, [[STATE_IDENTIFIER, '1'], tokens[0]]], tokens[1:]]
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
        integer = integer * 0x100 + ord(byte)
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

def Transform(fIn, fIn2, fOut, commandPython):
    position = 0
    isPython3 = sys.version_info[0] > 2
    while True:
        inbyte = fIn.read(1)
        if not inbyte:
            break
        byte = ord(inbyte)
        if fIn2 != None:
            inbyte2 = fIn2.read(1)
            byte2 = ord(inbyte2)
        outbyte = eval(commandPython)
        if outbyte != None:
            if isPython3:
                fOut.write(bytes([outbyte]))
            else:
                fOut.write(chr(outbyte))
        position += 1

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

def Translate(filenameInput, commandPython, options):
    if filenameInput == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        try:
            fIn = sys.stdin.buffer
        except:
            fIn = sys.stdin
    else:
        decoded = FilenameCheckHash(filenameInput)
        if options.literalfilenames or decoded == '':
            fIn = open(filenameInput, 'rb')
        elif decoded == None:
            print('Error parsing filename: ' + filenameInput)
            return
        else:
            fIn = StringIO(decoded)

    if options.secondbytestream != '':
        decoded = FilenameCheckHash(options.secondbytestream)
        if options.literalfilenames or decoded == '':
            fIn2 = open(options.secondbytestream, 'rb')
        elif decoded == None:
            print('Error parsing filename: ' + options.secondbytestream)
            return
        else:
            fIn2 = StringIO(decoded)
    else:
        fIn2 = None

    if options.output == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        try:
            fOut = sys.stdout.buffer
        except:
            fOut = sys.stdout
    else:
        fOut = open(options.output, 'wb')

    if options.script != '':
        exec(open(options.script, 'r').read(), globals())

    if options.execute != '':
        exec(options.execute, globals())

    if options.fullread:
        Output(fOut, eval(commandPython)(fIn.read()))
    elif options.regex != '' or options.filterregex != '':
        content = fIn.read()
        if options.regex != '':
            if sys.version_info[0] > 2:
                regexvalue = options.regex.encode()
            else:
                regexvalue = options.regex
            Output(fOut, re.sub(regexvalue, eval(commandPython), content))
        else:
            if sys.version_info[0] > 2:
                regexvalue = options.filterregex.encode()
            else:
                regexvalue = options.filterregex
            Output(fOut, re.sub(regexvalue, eval(commandPython), b''.join([x.group() for x in re.finditer(regexvalue, content)])))
    else:
        Transform(fIn, fIn2, fOut, commandPython)

    if fIn != sys.stdin:
        fIn.close()
    if fIn2 != None:
        fIn2.close()
    if fOut != sys.stdout:
        fOut.close()

def Main():
    moredesc = '''

Example: translate.py -o svchost.exe.dec svchost.exe 'byte ^ 0x10'
"byte" is the current byte in the file, 'byte ^ 0x10' does an X0R 0x10
Extra functions:
  rol(byte, count)
  ror(byte, count)
  shl(bytes, count)
  shr(bytes, count)
  IFF(expression, valueTrue, valueFalse)
  Sani1(byte)
  Sani2(byte)
  ZlibD(bytes)
  ZlibRawD(bytes)
  GzipD(bytes)
Variable "position" is an index into the input file, starting at 0

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file-in] [file-out] command [script]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-o', '--output', default='', help='Output file (default is stdout)')
    oParser.add_option('-s', '--script', default='', help='Script with definitions to include')
    oParser.add_option('-f', '--fullread', action='store_true', default=False, help='Full read of the file')
    oParser.add_option('-r', '--regex', default='', help='Regex to search input file for and apply function to')
    oParser.add_option('-R', '--filterregex', default='', help='Regex to filter input file for and apply function to')
    oParser.add_option('-e', '--execute', default='', help='Commands to execute')
    oParser.add_option('-2', '--secondbytestream', default='', help='Second bytestream')
    oParser.add_option('-l', '--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='print manual')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0 or len(args) > 4:
        oParser.print_help()
    elif len(args) == 1:
        Translate('', args[0], options)
    elif len(args) == 2:
        Translate(args[0], args[1], options)
    elif len(args) == 3:
        options.output = args[1]
        Translate(args[0], args[2], options)
    elif len(args) == 4:
        options.output = args[1]
        options.script = args[3]
        Translate(args[0], args[2], options)

if __name__ == '__main__':
    Main()
