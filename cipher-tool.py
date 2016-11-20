#!/usr/bin/env python

__description__ = 'Cipher tool'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/11/20'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/11/13: start
  2016/11/18: continue
  2016/11/20: man

Todo:
 add cut option
"""

import optparse
import textwrap
import binascii
import collections
import zipfile
import sys
import os

MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

cipher-tool is a tool to encode and decode with simple ciphers.

cipher-tool takes two or three arguments. The first argument is the cipher to use. Supported ciphers are:
xor
sub (subtract)
rot
vig (vigenere)

The second argument is a file containing the plaintext or ciphertext, the third argument is a file containing the key. This third argument is not used for ciphers like rot.
The files can also be ZIP files containing one file (optionally password-protected with 'infected'), in that case cipher-tool will decompress the content of the ZIP file and use it.

In stead of putting the plaintext or the ciphertext in a file, it can also be passed in the argument. To achieve this, precede the text with character #.
If the text to pass via the argument contains control characters or non-printable characters, hexadecimal (#h#) or base64 (#b#) can be used.

Example:
cipher-tool.py rot "#This is a secret message!"
Guvf vf n frperg zrffntr!

Ciphers:

xor: this cipher (XOR operation) requires plaintext/ciphertext and a key. Options -d and -o have no effect on this cipher.
Example:
cipher-tool.py xor #h#070D0A01451D20450252161130170606451936161013021172 #Secret
This is a secret message!

sub: this cipher (subtract operation) requires ciphertext and a key. Options -d and -o have no effect on this cipher. All characters both found in the ciphertext and the key, are removed (subtracted) from the ciphertext, thus producing the plaintext.
Example:
cipher-tool.py sub #aahbtctbbp:4//4127.560.045.14abba #abc456
http://127.0.0.1

rot: this cipher (rotation operation) requires plaintext/ciphertext, but no key argument. By default, this cipher encodes messages. To decode messages, use option -d. The offset used by default for rotating is 13 (rot-13). The offset can be changed with option -o.
Example encoding with Caesar cipher (rot-3):
cipher-tool.py rot -o 3 "#This is a secret message!"
Wklv lv d vhfuhw phvvdjh!
Example decoding with Caesar cipher (rot-3):
cipher-tool.py rot -d -o 3 "#Wklv lv d vhfuhw phvvdjh!"
This is a secret message!

vig: this cipher (Vigenere operation) requires plaintext/ciphertext and a	key. By default, this cipher encodes messages. To decode messages, use option -d. The offset used by default is 0 (Vigenere). The offset can be changed with option -o.
Example:
cipher-tool.py vig "#This is a secret message!" #Secret
Llkj ml s wgtvxl qgjwtyi!

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

def File2StringHash(filename):
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
    elif filename.startswith('#'):
        return filename[1:]
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

def SubtractData(data, key):
    return ''.join([c for c in data if not c in key])

def VigenereData(data, key, decode, offset):
    result = ''
    iter = 0
    for c in data:
        if c.isalpha():
            if c.islower():
                caseOffset = ord('a')
            else:
                caseOffset = ord('A')
            i = ord(c) - caseOffset
            keyindex = ord(key[iter % len(key)].lower()) - ord('a') + offset
            if decode:
                keyindex = -keyindex
            i = (i + keyindex) % 26
            result += chr(i + caseOffset)
            iter += 1
        else:
            result += c
    return result            
    
def ROTData(data, decode, offset):
    result = ''
    if offset == 0:
        offset = 13
    if decode:
        offset = 26 - offset
    for c in data:
        if c.isalpha():
            if c.islower():
                caseOffset = ord('a')
            else:
                caseOffset = ord('A')
            i = ord(c) - caseOffset
            i = (i + offset) % 26
            result += chr(i + caseOffset)
        else:
            result += c
    return result            
    
def CipherTool(operation, filenameCiphertext, filenameKey, options):
    if filenameKey == None and operation != 'rot':
        print('Missing key')
        return
    elif filenameKey != None:
        key = File2StringHash(filenameKey)
        if key == None:
            print('Error reading: %s' % filenameKey)
            return
    ciphertext = File2StringHash(filenameCiphertext)
    if ciphertext == None:
        print('Error reading: %s' % filenameCiphertext)
        return

    if operation == 'sub':
        data = SubtractData(ciphertext, key)
    elif operation == 'xor':
        data = XORData(ciphertext, key)
    elif operation == 'vig':
        data = VigenereData(ciphertext, key, options.decode, options.offset)
    elif operation == 'rot':
        data = ROTData(ciphertext, options.decode, options.offset)
    else:
        print('Unknown operation: %s' % operation)
        return

    IfWIN32SetBinary(sys.stdout)
    StdoutWriteChunked(data)

def Main():
    moredesc = '''
Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] operation filename-ciphertext [filename-key]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-d', '--decode', action='store_true', default=False, help='Decode operation (encode is default)')
    oParser.add_option('-o', '--offset', type=int, default=0, help='Offset (by default 13 for rot, 0 for vig)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 2 and len(args) != 3:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 2:
        CipherTool(args[0], args[1], None, options)
    else:
        CipherTool(args[0], args[1], args[2], options)

if __name__ == '__main__':
    Main()
