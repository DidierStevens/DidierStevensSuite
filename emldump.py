#!/usr/bin/env python

__description__ = 'EML dump utility'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/03/01'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2015/03/01: added Multipart flag
  2015/05/08: 0.0.2 added ZIP support

Todo:
"""

import optparse
import email
import hashlib
import signal
import sys
import os
import zipfile

MALWARE_PASSWORD = 'infected'

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

dumplinelength = 16

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
    return hexDump + '  ' + (' ' * (3 * (16 - len(asciiDump)))) + asciiDump

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
        asciiDump += IFF(ord(b) >= 32 and ord(b), b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        sys.stdout.flush()
        data = data[10000:]

def EMLDump(emlfilename, options):
    FixPipe()
    if emlfilename == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        data = sys.stdin.read()
    elif emlfilename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(emlfilename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        data = oZipContent.read()
        oZipContent.close()
        oZipfile.close()
    else:
        data = File2String(emlfilename)
    if options.header:
        data = data[data.find('\n') + 1:]
    oEML = email.message_from_string(data)
    if options.select == '':
        counter = 1
        for oPart in oEML.walk():
            print('%d: %s %s' % (counter, IFF(oPart.is_multipart(), 'M', ' '), oPart.get_content_type()))
            counter += 1
    else:
        if options.dump:
            DumpFunction = lambda x:x
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        elif options.hexdump:
            DumpFunction = HexDump
        else:
            DumpFunction = HexAsciiDump
        counter = 1
        for oPart in oEML.walk():
            if counter == int(options.select):
                StdoutWriteChunked(DumpFunction(oPart.get_payload(decode=True)))
                break
            counter += 1

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] mimefile\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='skip first line')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping')
    (options, args) = oParser.parse_args()

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 1:
        EMLDump(args[0], options)
    else:
        EMLDump('', options)

if __name__ == '__main__':
    Main()
