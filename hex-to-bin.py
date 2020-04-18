#!/usr/bin/env python

__description__ = 'Hex to bin'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2020/04/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2015/12/20: added stdin support
  2016/01/06: changed name from hex2bin.py to hex-to-bin.py; added man
  2019/05/07: added option -a
  2019/05/11: added option -l and -s
  2019/08/31: 0.0.3 added option -x
  2019/09/11: updated man; Python3 kludge
  2020/02/05: 0.0.4 added --bitstream
  2020/04/15: 0.0.5 added option --hexonly
  2020/04/16: added option --upperonly and --loweronly

Todo:
  Get rid of Python2/Python3 conversion kludge
"""

import optparse
import binascii
import sys
import os
import signal
import textwrap
import codecs
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO

def PrintManual():
    manual = '''
Manual:

This program reads from the given file or standard input, and converts the hexadecimal or bitstream data to binary data.
Unless option -b --bitstream is used, this tool converts hexadecimal data.

By default, this tool ignores whitespace.
When option -H (--hexonly) is used, all input characters except hexadecimal digits are ignored. This option can be combined with --upperonly (hex digits have to be uppercase) or with --loweronly (hex digits have to be lowercase).

Using option -a, this tool will look for the first hexadecimal/ASCII dump (see example below) as produced by other tools developed by Didier Stevens, and extract the contained hexadecimal data to convert to binary data.

File: demo.bin
Magic header found, dumping data:
00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
00000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

With option -a, the tool looks for string 00000000:.

Option -s can be used to select another hexadecimal/ASCII dump than the first one (for example, -s 2 to select the second dump).

Option -l (list) can be used to produce an overview of all hexadecimal/ASCII dumps found in the input, together with an index number to be used with option -s.

Using option -x, this tool will look for the first generic hexadecimal dump produced by other tools NOT developed by Didier Stevens (like registry export), and extract the contained hexadecimal data to convert to binary data.
An hexadecimal dump needs to start with at least 16 hexadecimal bytes (not interrupted by other letters or digits) to be recognized.
Options -l and -s can be used together with option -x.

Option -b makes this tool read bitstream data: this is text composed of 0 and 1 characters (whitespace is ignored).
Each consecutive group of 8 bits (0 or 1 characters) is converted to a byte. The left-most bit is the most significant bit.
If necessary, the bitstream is right-padded with 0s to make the bitstream length a multiple of 8.

hex-to-bin expects text input (ASCII). When the input is UNICODE, option -t can be used to translate the input text before it is parsed.
For example, -t utf16 will convert the input text from UTF16.

The binary data is written to standard output.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)
#Convert 2 Chr If Python 3
def C2CIP3(data):
    if sys.version_info[0] > 2:
        return chr(data)
    else:
        return data

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

#Fix for http://bugs.python.org/issue11395
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

def FindBeginHEXASCIIDump(data):
    positions = []
    position = 0
    while position != -1:
        position = data.find(C2BIP3('00000000: '), position)
        if position != -1:
            if position == 0 or data[position - 1] == '\x0A':
                positions.append(position)
                position += 1
    return positions

def ExtractHEXASCIIDump(data, select):
    positionColon = 8
    lengthHexadecimal = 48
    positions = FindBeginHEXASCIIDump(data)
    if positions == []:
        return ''
    result = C2BIP3('')
    for line in data[positions[select - 1]:].split(C2BIP3('\n')):
        line = line.strip()
        if len(line) <= positionColon:
            break
        if line[positionColon] == ':' or line[positionColon] == 0x3A:
            result += line[positionColon + 2:positionColon + 2 + lengthHexadecimal] + C2BIP3('\n')
        else:
            break
    return result

def IsRelevant(item):
    if item == '':
        return False
    for char in item:
        if C2CIP3(char).lower() in 'abcdefghijklmnopqrstuvwxyz' or C2CIP3(char) in '0123456789':
            return True
    return False

def IsHexByte(item):
    if len(item) != 2:
        return False
    for char in item:
        if not C2CIP3(char).lower() in '0123456789abcdef':
            return False
    return True

def ExtractContiguousHexBytes(line):
    line = line.rstrip(C2BIP3('\r\n'))
    items = [item for item in line.replace(C2BIP3('\t'), C2BIP3(' ')).replace(C2BIP3(','), C2BIP3(' ')).replace(C2BIP3(':'), C2BIP3(' ')).split(C2BIP3(' ')) if IsRelevant(item)]
    result = []
    for item in items:
        if IsHexByte(item):
            result.append(item)
        elif len(result) != 0:
            return result
    return result

def HEXDumpExtractOrProduceList(data, select, produceList):
    hexdump = C2BIP3('')
    counter = 0
    for line in data.split(C2BIP3('\n')):
        result = ExtractContiguousHexBytes(line)
        if hexdump != C2BIP3(''):
            if len(result) == 0:
                if counter == select and not produceList:
                    return hexdump
                else:
                    hexdump = C2BIP3('')
            else:
                hexdump += C2BIP3('').join(result)
        elif len(result) >= 16:
            counter += 1
            if produceList:
                print('%d: %s' % (counter, line))
            hexdump = C2BIP3('').join(result)
    return hexdump

def ListHEXASCIIDumps(data):
    for index, position in enumerate(FindBeginHEXASCIIDump(data)):
        print('%d: %s' % (index + 1, data[position:].split('\n')[0]))

def Translate(expression):
    try:
        codecs.lookup(expression)
        command = '.decode("%s")' % expression
    except LookupError:
        command = expression
    return lambda x: eval('x' + command)

def DecodeBitstream(bitstream):
    bitstream += ((8 - len(bitstream) % 8) % 8) * b'0'
    oResult = DataIO()
    position = 0
    while position < len(bitstream):
        oResult.write(C2BIP3(chr(int(bitstream[position:position + 8], 2))))
        position += 8
    return oResult.getvalue()

def Hex2Bin(filename, options):
    FixPipe()
    if filename == '':
        content = C2BIP3(sys.stdin.read())
    else:
        content = File2String(filename)
    if options.translate != '':
        content = C2BIP3(Translate(options.translate)(content))
    if options.list:
        if options.hexdump:
            HEXDumpExtractOrProduceList(content, int(options.select), True)
        else:
            ListHEXASCIIDumps(content)
        return
    if options.asciidump:
        content = ExtractHEXASCIIDump(content, int(options.select))
    elif options.hexdump:
        content = HEXDumpExtractOrProduceList(content, int(options.select), False)
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    if options.hexonly:
        hexdigits = b'0123456789abcdefABCDEF'
        if options.upperonly:
            hexdigits = b'0123456789ABCDEF'
        if options.loweronly:
            hexdigits = b'0123456789abcdef'
        if sys.version_info[0] >= 3:
            y = bytes([b for b in content if b in list(hexdigits)])
        else:
            y = b''.join([b for b in content if b in hexdigits])
    else:
        y = content.replace(C2BIP3(' '), C2BIP3('')).replace(C2BIP3('\t'), C2BIP3('')).replace(C2BIP3('\r'), C2BIP3('')).replace(C2BIP3('\n'), C2BIP3(''))
    if options.bitstream:
        data = DecodeBitstream(y)
    else:
        data = binascii.unhexlify(y)
    StdoutWriteChunked(data)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='Extract Hex/ASCII dump from other tools')
    oParser.add_option('-l', '--list', action='store_true', default=False, help='List all Hex/ASCII dumps')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='Extract Hex dumps')
    oParser.add_option('-s', '--select', default='1', help='Select dump nr for extraction (default first dump)')
    oParser.add_option('-t', '--translate', type=str, default='', help='String translation, like utf16 or .decode("utf8")')
    oParser.add_option('-b', '--bitstream', action='store_true', default=False, help='Process a bitstream (string with 0s & 1s)')
    oParser.add_option('-H', '--hexonly', action='store_true', default=False, help='Ignore all non-hex characters')
    oParser.add_option('--upperonly', action='store_true', default=False, help='Hex characters must be uppercase')
    oParser.add_option('--loweronly', action='store_true', default=False, help='Hex characters must be lowercase')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        Hex2Bin('', options)
    else:
        Hex2Bin(args[0], options)

if __name__ == '__main__':
    Main()
