#!/usr/bin/env python

__description__ = 'XOR known-plaintext attack'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2016/01/10'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/12/09: start
  2015/12/10: continue
  2015/12/15: continue
  2016/01/10: 0.0.2 added support for zipfiles

Todo:
"""

import optparse
import textwrap
import binascii
import collections
import zipfile
import sys

MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

Filename:
example
#content
#h#636F6E74656E74
#b#Y29udGVudA==

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

    return result

def XOR(filenamePlaintext, filenameCiphertext, options):
    nKeydata = collections.namedtuple('keydata', 'extra keystream key')

    plaintext = File2StringHash(filenamePlaintext)
    if plaintext == None:
        print('Error reading: %s' % filenamePlaintext)
        return
    ciphertext = File2StringHash(filenameCiphertext)
    if ciphertext == None:
        print('Error reading: %s' % filenameCiphertext)
        return

    results = []
    for i in range(len(ciphertext) - len(plaintext)):
        extractedKeyStream = XORData(plaintext, ciphertext[i:])
        keys = FilterKeys(SplitKey(extractedKeyStream))
        if len(keys) == 1:
            key = keys[0]
            start = len(key) - i % len(key)
            results.append(nKeydata(len(extractedKeyStream) - len(keys[0]), extractedKeyStream, key[start:] + key[0:start]))
        elif len(keys) > 1:
            print('Found more than one repeating key in key stream')
            print('Extracted key stream: %s' % repr(extractedKeyStream))
            print(keys)

    results = [result for result in results if result.extra >= options.extra]
    if len(results) == 0:
        print('No key found')
        return

    results = sorted(results, reverse=True)
    if options.decode:
        print(XORData(ciphertext, results[0].key))
    else:
        oPrintSeparatingLine = cPrintSeparatingLine()
        for result in results:
            oPrintSeparatingLine.Print()
            print('Key:       %s' % ReprIfNeeded(result.key))
            print('Extra:     %s' % result.extra)
            print('Keystream: %s' % ReprIfNeeded(result.keystream))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] filename-plaintext filename-ciphertext\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-e', '--extra', type=int, default=1, help='Minimum number of extras')
    oParser.add_option('-d', '--decode', action='store_true', default=False, help='Decode the ciphertext')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        XOR(args[0], args[1], options)

if __name__ == '__main__':
    Main()
