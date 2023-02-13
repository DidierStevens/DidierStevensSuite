#!/usr/bin/env python

__description__ = 'XOR known-plaintext attack'
__author__ = 'Didier Stevens'
__version__ = '0.0.7'
__date__ = '2023/02/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/12/09: start
  2015/12/10: continue
  2015/12/15: continue
  2016/01/10: 0.0.2 added support for zipfiles
  2016/08/01: 0.0.3 added support for pipes
  2016/08/02: added option -n
  2016/11/08: 0.0.4 added option -x
  2016/11/16: added key in hex
  2016/11/18: updated man
  2017/06/03: 0.0.5 added #e# support; changed output
  2017/06/04: continued #e# support
  2017/06/16: 0.0.6 continued #e# support
  2022/09/04: Python 3 upgrade, added plaintexts
  2023/02/12: 0.0.7 added plaintexts cs-key-mod

Todo:
  updated man starting changes 2017/06/03
"""

import optparse
import textwrap
import binascii
import collections
import sys
import os
import re
import random
try:
    import pyzipper as zipfile
except ImportError:
    import zipfile

MALWARE_PASSWORD = 'infected'

def XORData(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

dPlaintext = {
    'dos': b'This program cannot be run in DOS mode',
    'cs-key':     b'\x00\x07\x00\x03\x01\x00\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81',
    'cs-key-dot': b'\x2E\x29\x2E\x2D\x2F\x2E\x1E\xAF\xB1\x1E\x23\x28\x27\x04\xA8\x66\xA8\xD9\x23\x2F\x2F\x2F\x2B\x2E\x2D\xAF\xA3\x2E\x1E\xAF\xA7\x2C\xAF',
    'cs-key-i':   b'\x69\x6E\x69\x6A\x68\x69\x59\xE8\xF6\x59\x64\x6F\x60\x43\xEF\x21\xEF\x9E\x64\x68\x68\x68\x6C\x69\x6A\xE8\xE4\x69\x59\xE8\xE0\x6B\xE8',
    'cs-key-mod': b'\x02\x03\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
}
dPlaintext['cs-key-mod-dot'] = XORData(dPlaintext['cs-key-mod'], b'.')
dPlaintext['cs-key-mod-i'] = XORData(dPlaintext['cs-key-mod'], b'i')

def PrintManual():
    manual = '''
Manual:

xor-kpa performs a known-plaintext attack (KPA) on an XOR-encoded file. Take a file with content "This is a secret message, do not share!". This file is XOR-encoded like this: the key is ABC, the first byte of the file is XORed with A, the second byte of the file is XORed with B, the third byte of the file is XORed with C, the fourth byte of the file is XORed with A, the fifth byte of the file is XORed with B, ...
If you know part of the plaintext of this file, and that plaintext is longer than the key, then xor-kpa can recover the key.

xor-kpa tries to recover the key as follows. xor-kpa encodes the encoded file with the provided plaintext: if you XOR-encode an XOR-encoded file (ciphertext) again with its plaintext, then the result is the keystream (the key repeated): ABCABCABC... xor-kpa detects such keystreams and extracts the key.

Example:
 xor-kpa.py "#secret message" encoded.txt
Output:
 Key:       ABC
 Key (hex): 0x414243
 Extra:     11
 Divide:    4
 Counts:    1
 Keystream: BCABCABCABCABC

In this example, we assume that the plaintext contains "secret message". xor-kpa finds one keystream: BCABCABCABCABC. From this keystream, xor-kpa extracts the key: ABC.
Extra is the number of extra charecters in the keystream: the keystream is 14 characters longh, the key is 3 characters long, so extra is 14 - 3 = 11. It is a measure for the probability that the recovered key is the actual key. The longer it is, the better.
In this case, because the ciphertext is a small file, xor-kpa found only one keystream. But for larger files or small plaintext, it will identify more than one potential keystream.

Example:
 xor-kpa.py #secret encoded.txt
Output:
 Key:       'KU\x11W^'
 Key (hex): 0x4b5511575e
 Extra:     1
 Divide:    1
 Counts:    1
 Keystream: '^KU\x11W^'

 Key:       '\x07S@E\x1f'
 Key (hex): 0x075340451f
 Extra:     1
 Divide:    1
 Counts:    1
 Keystream: 'S@E\x1f\x07S'

 Key:       ABC
 Key (hex): 0x414243
 Extra:     3
 Divide:    2
 Counts:    1
 Keystream: BCABCA

In this example, xor-kpa has identified 3 potential keys. The potential keys are sorted by ascending extra-value. So the most promising keys are listed last.
Keystreams with an extra value of 1 (1 extra character) rarely contain the correct key.
Option -e (--extra) allows us to reduce the amount of displayed potential keys by specifying the minimum value for extras.

Example:
 xor-kpa.py -e 2 #secret encoded.txt
Output:
 Key:       ABC
 Key (hex): 0x414243
 Extra:     3
 Keystream: BCABCA

With option -e 2 we specify that the keystream must at least have 2 extras. That's why the keystreams with 1 extra are not listed.

xor-kpa can also decode the ciphertext file with the recovered key (the key with the highest extra value). Use option -d (--decode) to do this:

Example:
 xor-kpa.py -d #secret encoded.txt
Output:
 This is a secret message, do not share!

Using option -x xor-kpa can encode/decode a message with a provided key.
Example:
 xor-kpa.py -x #h#152A2A32622A32622261312622302635622E2431302025266D62272E622D2E3663322A22332762 #ABC
Output:
 This is a secret message, do not share!

xor-kpa takes one or two arguments. The first argument is a file containing the plaintext, the second argument is a file containing the ciphertext.
xor-kpa can also read the ciphertext from stdin (for example via a pipe), in that case the second argument is omitted.
The files can also be ZIP files containing one file (optionally password-protected with 'infected'), in that case xor-kpa will decompress the content of the ZIP file and use it.

In stead of putting the plaintext or the ciphertext in a file, it can also be passed in the argument. To achieve this, precede the text with character # (this is what we have done in all the examples up till now).
If the text to pass via the argument contains control characters or non-printable characters, hexadecimal (#h#) or base64 (#b#) can be used.

Example:
 xor-kpa.py -d #h#736563726574 encoded.txt
Output:
 This is a secret message, do not share!

Example:
 xor-kpa.py -d #b#c2VjcmV0 encoded.txt
Output:
 This is a secret message, do not share!

Finally, the plaintext can be selected from a predefined list. For the moment, the only text in the predefined list is 'This program cannot be run in DOS mode', identified by the keyword dos. Use option -n (--name) to use predefined plaintext.

Example:
 xor-kpa.py -n dos malware.vir

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 78))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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

def InterpretHexInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith('0x'):
        return None
    hex = token[1][2:]
    if len(hex) % 2 == 1:
        hex = '0' + hex
    try:
        bytes = binascii.a2b_hex(hex)
    except:
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
    try:
        return binascii.a2b_hex(token[1][2:])
    except:
        return None

def CheckFunction(functionname, arguments, countarguments):
    if countarguments == 0 and len(arguments) != 0:
        print('Error: function %s takes no arguments, %d are given' % (functionname, len(arguments)))
        return True
    if countarguments == 1 and len(arguments) != 1:
        print('Error: function %s takes 1 argument, %d are given' % (functionname, len(arguments)))
        return True
    if countarguments != len(arguments):
        print('Error: function %s takes %d arguments, %d are given' % (functionname, countarguments, len(arguments)))
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
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1, maximum=255)
            if number == None:
                return None
            decoded += chr(number)
        else:
            print('Error: unknown function: %s' % functionname)
            return None
    return decoded

def FilenameCheckHash(filename):
    decoded = None
    if filename.startswith('#h#'):
        try:
            decoded = binascii.a2b_hex(filename[3:])
        finally:
            return decoded
    elif filename.startswith('#b#'):
        try:
            decoded = binascii.a2b_base64(filename[3:])
        finally:
            return decoded
    elif filename.startswith('#e#'):
        return Interpret(filename[3:])
    elif filename.startswith('#'):
        return filename[1:].encode('latin')
    else:
        return b''

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

def File2StringHash(filename):
    decoded = FilenameCheckHash(filename)
    if decoded != b'':
        return decoded
    elif filename.lower().endswith('.zip'):
        oZipfile = CreateZipFileObject(filename, 'r')
        if len(oZipfile.infolist()) == 1:
            oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
            data = oZipContent.read()
            oZipContent.close()
        else:
            data = File2String(filename)
        oZipfile.close()
        return data
    else:
        return File2String(filename)

def ReprIfNeeded(data):
    if b"'" + data + b"'" == repr(data):
        return data
    else:
        return repr(data)

class cPrintSeparatingLine():
    def __init__(self):
        self.first = True

    def Print(self, line=''):
        if self.first:
            self.first = False
        else:
            print(line)

def SplitKey(extractedKeyStream):
    result = []
    for i in range(2, len(extractedKeyStream)):
        temp = extractedKeyStream
        keys = []
        while temp != b'':
            keys.append(temp[0:i])
            temp = temp[i:]
        result.append(keys)
    return result

def FilterKeys(keyss):
    result = []
    for keys in keyss:
        while len(keys) > 2 and keys[0] == keys[1]:
            keys = keys[1:]
        if len(keys) == 2 and keys[0][0:len(keys[1])] == keys[1]:
            result.append(keys[0])

    while len(result) > 1:
        if result[0] * int(len(result[1]) / len(result[0])) == result[1]:
            del result[1]
        else:
            break

    return result

def XOR(filenamePlaintext, filenameCiphertext, options):
    global dPlaintext

    nKeydata = collections.namedtuple('keydata', 'extra keystream key')

    if options.name:
        if filenamePlaintext.lower() in dPlaintext:
            plaintext = dPlaintext[filenamePlaintext.lower()]
        else:
            print('Unknown name for plaintext: %s' % options.name)
            return
    else:
        plaintext = File2StringHash(filenamePlaintext)
        if plaintext == None:
            print('Error reading: %s' % filenamePlaintext)
            return
    if filenameCiphertext == '':
        ciphertext = sys.stdin.buffer.read()
    else:
        ciphertext = File2StringHash(filenameCiphertext)
        if ciphertext == None:
            print('Error reading: %s' % filenameCiphertext)
            return

    if options.xor:
        sys.stdout.buffer.write(XORData(plaintext, ciphertext))
        return

    results = []
    for i in range(len(ciphertext) - len(plaintext)):
        extractedKeyStream = XORData(plaintext, ciphertext[i:])
        keys = FilterKeys(SplitKey(extractedKeyStream))
        if len(keys) == 1:
            key = keys[0]
            start = len(key) - i % len(key)
            results.append(nKeydata(len(extractedKeyStream) - len(keys[0]), extractedKeyStream, key[start:] + key[0:start]))
        elif len(keys) > 1 and options.verbose:
            print('Found more than one repeating key in key stream')
            print('Extracted key stream: %s' % repr(extractedKeyStream))
            print(keys)

    results = [result for result in results if result.extra >= options.extra]
    if len(results) == 0:
        print('No key found')
        return

    dKeys = {}
    reduced = []
    for result in sorted(results, key=lambda x: x.extra, reverse=True):
        if result.key in dKeys:
            dKeys[result.key] += 1
        else:
            dKeys[result.key] = 1
            reduced.insert(0, result)
    if options.decode:
        sys.stdout.buffer.write(XORData(ciphertext, reduced[-1].key))
    else:
        oPrintSeparatingLine = cPrintSeparatingLine()
        for result in reduced:
            oPrintSeparatingLine.Print()
            print('Key:       %s' % ReprIfNeeded(result.key))
            print('Key (hex): 0x%s' % binascii.b2a_hex(result.key).decode())
            print('Extra:     %s' % result.extra)
            print('Divide:    %d' % (len(result.keystream) / len(result.key)))
            print('Counts:    %d' % dKeys[result.key])
            print('Keystream: %s' % ReprIfNeeded(result.keystream))

def Main():
    global dPlaintext

    moredesc = '''

Predefined plaintext:
'''

    for key in sorted(dPlaintext.keys()):
        moredesc += ' %s: %s\n' % (key, dPlaintext[key])

    moredesc += '''
Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] filename-plaintext [filename-ciphertext]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-n', '--name', action='store_true', default=False, help='Use predefined plaintext')
    oParser.add_option('-e', '--extra', type=int, default=2, help='Minimum number of extras')
    oParser.add_option('-d', '--decode', action='store_true', default=False, help='Decode the ciphertext')
    oParser.add_option('-x', '--xor', action='store_true', default=False, help='XOR data with key')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='Verbose output')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 1 and len(args) != 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 1:
        XOR(args[0], '', options)
    else:
        XOR(args[0], args[1], options)

if __name__ == '__main__':
    Main()
