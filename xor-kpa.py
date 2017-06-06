#!/usr/bin/env python

__description__ = 'XOR known-plaintext attack'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2017/06/04'

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

Todo:
  updated man starting changes 2017/06/03
"""

import optparse
import textwrap
import binascii
import collections
import zipfile
import sys
import os
import re
import random

MALWARE_PASSWORD = 'infected'
dPlaintext = {'dos': 'This program cannot be run in DOS mode'}

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

def FilenameCheckHashExpression(expression):
    oMatch = re.match(r'repeat\((\d+),(0x[0-9a-fA-F]+)\)$', expression)
    if oMatch != None:
        try:
            return int(oMatch.groups()[0]) * binascii.a2b_hex(oMatch.groups()[1][2:])
        except:
            return None
    else:
        oMatch = re.match(r'random\((\d+)\)$', expression)
        if oMatch != None:
            try:
                return ''.join([chr(random.randint(0, 255)) for x in range(int(oMatch.groups()[0]))])
            except:
                return None
        else:
            oMatch = re.match(r'loremipsum\((\d+)\)$', expression)
            if oMatch != None:
                try:
                    return LoremIpsum(int(oMatch.groups()[0]))
                except:
                    return None
            else:
                return None

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
        decoded = ''
        for expression in filename[3:].split('+'):
            result = FilenameCheckHashExpression(expression)
            if result == None:
                return None
            else:
                decoded += result
        return decoded
    elif filename.startswith('#'):
        return filename[1:]
    else:
        return ''

def File2StringHash(filename):
    decoded = FilenameCheckHash(filename)
    if decoded != '':
        return decoded
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
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

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def ReprIfNeeded(data):
    if "'" + data + "'" == repr(data):
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

def XORData(data, key):
    return ''.join([chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data))])

def SplitKey(extractedKeyStream):
    result = []
    for i in range(2, len(extractedKeyStream)):
        temp = extractedKeyStream
        keys = []
        while temp != '':
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
        if result[0] * (len(result[1]) / len(result[0])) == result[1]:
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
        IfWIN32SetBinary(sys.stdin)
        ciphertext = sys.stdin.read()
    else:
        ciphertext = File2StringHash(filenameCiphertext)
        if ciphertext == None:
            print('Error reading: %s' % filenameCiphertext)
            return

    if options.xor:
        IfWIN32SetBinary(sys.stdout)
        StdoutWriteChunked(XORData(plaintext, ciphertext))
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
        IfWIN32SetBinary(sys.stdout)
        StdoutWriteChunked(XORData(ciphertext, reduced[-1].key))
    else:
        oPrintSeparatingLine = cPrintSeparatingLine()
        for result in reduced:
            oPrintSeparatingLine.Print()
            print('Key:       %s' % ReprIfNeeded(result.key))
            print('Key (hex): 0x%s' % binascii.b2a_hex(result.key))
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
    oParser.add_option('-e', '--extra', type=int, default=1, help='Minimum number of extras')
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
