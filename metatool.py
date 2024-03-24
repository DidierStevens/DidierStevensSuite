#!/usr/bin/env python

__description__ = "Tool for Metasploit"
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2024/03/24'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/08/17: start
  2021/03/11: 0.0.2 added command url8, Python 3 fix
  2021/03/21: 0.0.3 CS x64
  2024/03/24: 0.0.4 added option -a

Todo:
"""

import optparse
import glob
import collections
import sys
import textwrap
import gzip
import os
import re
import base64
import struct
import binascii
import time
import io

COMMANDS = ['urluuid', 'url8']
COMMANDS_URLUUID = 0
COMMANDS_URL8 = 1

def PrintManual():
    manual = '''
Manual:

This version of the tool recognizes and decodes 2 types of Metasploit URLs.

In this version the supported commands are: %s.

Example: metatool.py urluuid url.txt

Output:
URL: http://127.0.0.1:8080/4PGoVGYmx8l6F3sVI4Rc8g1wms758YNVXPczHlPobpJENARSuSHb57lFKNndzVSpivRDSi5VH2U-w-pEq_CroLcB--cNbYRroyFuaAgCyMCJDpWbws/
puid: e0f1a8546626c7c9 ('\xe0\xf1\xa8Tf&\xc7\xc9')
platform: 1 (windows)
architecture: 2 (ARCH_X64)
timestamp: 2017/08/15 18:52:53


Example: echo http://example.com/WsJH | metatool.py url8

Output:
URL: http://example.com/WsJH
path: WsJH
checksum: URI_CHECKSUM_INITW (0x5c)

To provide the URLs as command-line arguments (e.g., not contained in files), use option -a.

Example: metatool.py -a url8 http://example.com/WsJI

Output:
URL: http://example.com/WsJI
path: WsJI
checksum: CS x64 (0x5d)

''' % ', '.join(COMMANDS)
    for line in manual.split('\n'):
        print(textwrap.fill(line))

dArchitectures = {
     0: 'nil',
     1: 'ARCH_X86',
     2: 'ARCH_X64',
     3: 'ARCH_X64',
     4: 'ARCH_MIPS',
     5: 'ARCH_MIPSLE',
     6: 'ARCH_MIPSBE',
     7: 'ARCH_PPC',
     8: 'ARCH_PPC64',
     9: 'ARCH_CBEA',
    10: 'ARCH_CBEA64',
    11: 'ARCH_SPARC',
    12: 'ARCH_ARMLE',
    13: 'ARCH_ARMBE',
    14: 'ARCH_CMD',
    15: 'ARCH_PHP',
    16: 'ARCH_TTY',
    17: 'ARCH_JAVA',
    18: 'ARCH_RUBY',
    19: 'ARCH_DALVIK',
    20: 'ARCH_PYTHON',
    21: 'ARCH_NODEJS',
    22: 'ARCH_FIREFOX',
    23: 'ARCH_ZARCH',
    24: 'ARCH_AARCH64',
    25: 'ARCH_MIPS64',
    26: 'ARCH_PPC64LE'
}

dPlatforms = {
     0: 'nil',
     1: 'windows',
     2: 'netware',
     3: 'android',
     4: 'java',
     5: 'ruby',
     6: 'linux',
     7: 'cisco',
     8: 'solaris',
     9: 'osx',
    10: 'bsd',
    11: 'openbsd',
    12: 'bsdi',
    13: 'netbsd',
    14: 'freebsd',
    15: 'aix',
    16: 'hpux',
    17: 'irix',
    18: 'unix',
    19: 'php',
    20: 'js',
    21: 'python',
    22: 'nodejs',
    23: 'firefox'
  }

UNDEFINED = 'undefined'

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

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d/%02d/%02d %02d:%02d:%02d' % time.gmtime(epoch)[0:6]

class cOutput():
    def __init__(self, filename=None):
        self.filename = filename
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if self.f:
            self.f.write(line + '\n')
        else:
            print(line)
#            sys.stdout.flush()

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cOutputResult():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options

    def Line(self, line):
        self.oOutput.Line(line)

    def Close(self):
        self.oOutput.Close()

def ProcessFile(fIn, fullread):
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n\r')

def Checksum8(data):
    return sum(map(ord, data))

def Checksum8LSB(data):
    dMetasploitConstants = {
        92: 'URI_CHECKSUM_INITW / CS x86',
        93: 'CS x64',
        80: 'URI_CHECKSUM_INITP',
        88: 'URI_CHECKSUM_INITJ',
        98: 'URI_CHECKSUM_CONN',
        95: 'URI_CHECKSUM_INIT_CONN',
    }

    value = Checksum8(data) % 0x100
    return (value, dMetasploitConstants.get(value, ''))

def MetatoolSingle(command, filename, oOutput, options):
    if options.arguments:
        fIn = io.StringIO(filename)
    elif filename == '':
        fIn = sys.stdin
    elif os.path.splitext(filename)[1].lower() == '.gz':
        fIn = gzip.GzipFile(filename, 'rb')
    else:
        fIn = open(filename, 'r')
    oREurluuid = re.compile('(?:https?://[^/]+)?/([^/]+)/?')
    oREurl8 = re.compile(r'https?://[^/]+/(.{4})\b')
    format = '8sBBBBBBBB'
    for line in ProcessFile(fIn, False):
        if command == COMMANDS[COMMANDS_URLUUID]:
            oSearch = oREurluuid.search(line)
            if oSearch != None:
                if len(oSearch.groups()[0]) >= 22:
                    try:
                        decoded = base64.urlsafe_b64decode(oSearch.groups()[0][0:22] + '==')
                    except:
                        continue

                    if len(decoded) < struct.calcsize(format):
                        continue
                    puid, xor1, xor2, platform_xored, architecture_xored, ts1_xored, ts2_xored, ts3_xored, ts4_xored = struct.unpack(format, decoded)
                    platform = platform_xored ^ xor1
                    platformName = dPlatforms.get(platform, UNDEFINED)
                    if platformName == UNDEFINED and not options.force:
                        continue
                    architecture = architecture_xored ^ xor2
                    architectureName = dArchitectures.get(architecture, UNDEFINED)
                    if architectureName == UNDEFINED and not options.force:
                        continue
                    timestamp = struct.unpack('>I', bytes([ts1_xored ^ xor1, ts2_xored ^ xor2, ts3_xored ^ xor1, ts4_xored ^ xor2]))[0]
                    oOutput.Line('URL: %s' % (oSearch.string))
                    oOutput.Line('puid: %s (%s)' % (binascii.b2a_hex(puid), repr(puid)))
                    oOutput.Line('platform: %d (%s)' % (platform, platformName))
                    oOutput.Line('architecture: %d (%s)' % (architecture, architectureName))
                    oOutput.Line('timestamp: %s' % (FormatTime(timestamp)))
        elif command == COMMANDS[COMMANDS_URL8]:
            oSearch = oREurl8.search(line)
            if oSearch != None:
                path = oSearch.groups()[0]
                checksumValue, checksumConstant = Checksum8LSB(path)
                if checksumConstant != '' or options.force:
                    oOutput.Line('URL: %s' % (oSearch.group()))
                    oOutput.Line('path: %s' % path)
                    oOutput.Line('checksum: %s (0x%02x)' % (checksumConstant, checksumValue))

    if fIn != sys.stdin and type(fIn) != list:
        fIn.close()

def Metatool(command, filenames, options):
    if not command in COMMANDS:
        print('Unsupported command: %s' % command)
        print('Valid commands: %s' % ' '.join(COMMANDS))
        return
    oOutput = cOutputResult(options)
    for filename in filenames:
        MetatoolSingle(command, filename, oOutput, options)
    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] command [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-f', '--force', action='store_true', default=False, help='Force output for unrecognized data')
    oParser.add_option('-a', '--arguments', action='store_true', default=False, help='URLs provided as arguments')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
        return
    elif len(args) == 1:
        Metatool(args[0], [''], options)
    elif options.arguments:
        Metatool(args[0], args[1:], options)
    else:
        Metatool(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
