#!/usr/bin/env python

__description__ = 'Extract base64 strings from file'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/07/01'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/06/30: start
  2015/07/01: added header

Todo:
"""

import optparse
import sys
import os
import zipfile
import cStringIO
import binascii
import textwrap
import re
import hashlib

dumplinelength = 16
MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump

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
        hexDump+= ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

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

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def AsciiDump(data):
    return ''.join([IFF(ord(b) >= 32, b, '.') for b in data])

def BASE64Dump(filename, options):
    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    if options.dump:
        DumpFunction = lambda x:x
        IfWIN32SetBinary(sys.stdout)
    elif options.hexdump:
        DumpFunction = HexDump
    else:
        DumpFunction = HexAsciiDump

    if options.select == '':
        formatString = '%-2s  %-7s %-16s %-16s %-32s'
        columnNames = ('ID', 'Size', 'BASE64', 'Decoded', 'MD5 decoded')
        print(formatString % columnNames)
        print(formatString % tuple(['-' * len(s) for s in columnNames]))

    counter = 1
    data = oStringIO.read()
    for base64string in re.findall('[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]+={0,2}', data):
        if len(base64string) % 4 == 0:
            try:
                base64data = binascii.a2b_base64(base64string)
            except:
                break
            if options.select == '':
                print('%2d: %7d %-16s %-16s %s' % (counter, len(base64string), base64string[0:16], AsciiDump(base64data[0:16]), hashlib.md5(base64data).hexdigest()))
            elif ('%s' % counter) == options.select:
                StdoutWriteChunked(DumpFunction(base64data))
            counter += 1

    return 0

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    elif len(args) == 0:
        return BASE64Dump('', options)
    else:
        return BASE64Dump(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
