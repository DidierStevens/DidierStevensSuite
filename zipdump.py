#!/usr/bin/env python

__description__ = 'ZIP dump utility'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2014/08/14'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2014/04/30: added timestamp
  2014/08/14: added manual 

Todo:
"""

import optparse
import zipfile
import hashlib
import signal
import sys
import os
import cStringIO
import textwrap

STANDARD_MALWARE_SAMPLE_PASSWORD = 'infected'
QUOTE = '"'

def PrintManual():
    manual = '''
Manual:

zipdump allows you to inspect ZIP files.
By default, the output is a csv file with the filename, encrypted flag, md5 and timestamp of each file inside the zip file.

Example: zipdump.py test.zip
Output:
zipfilename;encrypted;MD5;Timestamp
file1.txt;0;23ac1d8f3680efd3b31fb988e6438cc5;2014-08-10 14:11:32
file2.txt;0;c749903dd4a3e98b26c7f58ec93fe808;2014-08-10 14:11:50

zipdump also accepts stdin, then you have to use - as filename:
cat test.zip | zipdump.py -

The contents of the compressed files can be dumped (-d), hexdumped (-x) and ascii dumped (-a).
If you do not provide a filename to dump, the first file is dumped.

Example:

zipdump.py -a files.zip
00000000: 46 69 72 73 74 20 66 69 6C 65 21 0D 0A 0D 0A 53  First file!....S
00000010: 6F 6D 65 20 64 61 74 61 2E                       ome data.

Example with the filename to dump:

zipdump.py -a files.zip file2.txt
00000000: 53 65 63 6F 6E 64 65 20 66 69 6C 65 21 0D 0A 0D  Seconde file!...
00000010: 0A 53 6F 6D 65 20 6D 6F 72 65 20 64 61 74 61 2E  .Some more data.

You can select another separator than ; for the csv file with option -s.
Option -o allows you to write the csv file to disk.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line +'\n')

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

def ZIPDump(zipfilename, targetfilename, options):
    FixPipe()
    if zipfilename == '-':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        oZipfile = zipfile.ZipFile(cStringIO.StringIO(sys.stdin.read()), 'r')
    else:
        oZipfile = zipfile.ZipFile(zipfilename, 'r')
    if options.output:
        fOut = open(options.output, 'w')
    else:
        fOut = None
    if options.dump or options.hexdump or options.asciidump:
        if options.dump:
            DumpFunction = lambda x:x
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        elif options.hexdump:
            DumpFunction = HexDump
        else:
            DumpFunction = HexAsciiDump
        for oZipInfo in oZipfile.infolist():
            if targetfilename == None or targetfilename == oZipInfo.filename:
                file = oZipfile.open(oZipInfo, 'r', STANDARD_MALWARE_SAMPLE_PASSWORD)
                StdoutWriteChunked(DumpFunction(file.read()))
                file.close()
                if targetfilename == None:
                    break
    else:
        Print(MakeCSVLine(['zipfilename', 'encrypted', 'MD5', 'Timestamp'], options.separator, QUOTE), fOut)
        for oZipInfo in oZipfile.infolist():
            if targetfilename == None or targetfilename == oZipInfo.filename:
                file = oZipfile.open(oZipInfo, 'r', STANDARD_MALWARE_SAMPLE_PASSWORD)
                filehash = hashlib.md5(file.read()).hexdigest()
                file.close()
                Print(MakeCSVLine([oZipInfo.filename, oZipInfo.flag_bits & 1, filehash, '%04d-%02d-%02d %02d:%02d:%02d' % oZipInfo.date_time], options.separator, QUOTE), fOut)
    if fOut:
        fOut.close()
    oZipfile.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] zipfile [filename]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--separator', default=';', help='Separator character (default ;)')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='print manual')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) < 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 1:
        ZIPDump(args[0], None, options)
    else:
        ZIPDump(args[0], args[1], options)

if __name__ == '__main__':
    Main()
