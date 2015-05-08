#!/usr/bin/env python

__description__ = 'Calculate the SSH fingerprint from a Cisco public key dumped with command "show crypto key mypubkey rsa"'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2014/08/19'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/12/20: start
  2011/12/30: added SplitPerXCharacters
  2014/08/19: fixed bug MatchLength

Todo:
"""

import optparse
import struct
import hashlib

def IsHexDigit(string):
    if string == '':
        return False
    for char in string:
        if not (char.isdigit() or char.lower() >= 'a' and char.lower() <= 'f'):
            return False
    return True

def HexDumpFile2Data(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        hex = ''.join(line.replace('\n', '').replace(' ', '') for line in f.readlines())
        if not IsHexDigit(hex):
            return None
        if len(hex) % 2 != 0:
            return None
        return ''.join(map(lambda x, y: chr(int(x+y, 16)), hex[::2], hex[1::2]))
    finally:
        f.close()

def MatchByte(byte, data):
    if len(data) < 1:
        return (data, False)
    if ord(data[0]) != byte:
        return (data, False)
    return (data[1:], True)

def MatchLength(data):
    if len(data) < 1:
        return (data, False, 0)
    if ord(data[0]) <= 0x80: #a# check 80
        return (data[1:], True, ord(data[0]))
    countBytes = ord(data[0]) - 0x80
    data = data[1:]
    if len(data) < countBytes:
        return (data, False, 0)
    length = 0
    for index in range(0, countBytes):
        length = ord(data[index]) + length * 0x100
    return (data[countBytes:], True, length)

def MatchString(string, data):
    if len(data) < len(string):
        return (data, False)
    if data[:len(string)] != string:
        return (data, False)
    return (data[len(string):], True)

def ParsePublicKeyDER(data):
    data, match = MatchByte(0x30, data)
    if not match:
        print('Parse error: expected sequence (0x30)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 1: %d' % length)
        return None

    data, match = MatchString('\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00', data)
    if not match:
        print('Parse error: expected OID rsaEncryption')
        return None

    data, match = MatchByte(0x03, data)
    if not match:
        print('Parse error: expected bitstring (0x03)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 2: %d' % length)
        return None

    data, match = MatchByte(0x00, data)
    if not match:
        print('Parse error: expected no padding (0x00)')
        return None

    data, match = MatchByte(0x30, data)
    if not match:
        print('Parse error: expected sequence (0x30)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 3: %d' % length)
        return None

    data, match = MatchByte(0x02, data)
    if not match:
        print('Parse error: expected integer (0x02)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 4: %d' % length)
        return None
    modulus = data[:length]
    data = data[length:]

    data, match = MatchByte(0x02, data)
    if not match:
        print('Parse error: expected integer (0x02)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 5: %d' % length)
        return None
    exponent = data[:length]

    return (modulus, exponent)

def LengthEncode(data):
    return struct.pack('>I', len(data)) + data

def CalcFingerprint(modulus, exponent):
    data = LengthEncode('ssh-rsa') + LengthEncode(exponent) + LengthEncode(modulus)
    return hashlib.md5(data).hexdigest()

def SplitPerXCharacters(string, count):
    return [string[iter:iter+count] for iter in range(0, len(string), count)]

def CiscoCalculateSSHFingerprint(filename):
    publicKeyDER = HexDumpFile2Data(filename)
    if publicKeyDER == None:
        print('Error reading public key')
        return
    result = ParsePublicKeyDER(publicKeyDER)
    if result == None:
        return
    fingerprint = CalcFingerprint(result[0], result[1])
    print(':'.join(SplitPerXCharacters(fingerprint, 2)))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog file\n' + __description__, version='%prog ' + __version__)
    (options, args) = oParser.parse_args()

    if len(args) != 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        CiscoCalculateSSHFingerprint(args[0])

if __name__ == '__main__':
    Main()
