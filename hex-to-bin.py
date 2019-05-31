#!/usr/bin/env python

__description__ = 'Hex to bin'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2019/05/11'

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

Todo:
"""

import optparse
import binascii
import sys
import os
import signal
import textwrap

def PrintManual():
    manual = '''
Manual:

This program reads from the given file or standard input, and converts the hexadecimal data to binary data.

Using option -a, this tool will look for the first hexadecimal/ASCII dump (see example below) as produced by other tools developed by Didier Stevens, and extract the contained hexadecimal data to convert to binary data.

File: demo.bin
Magic header found, dumping data:
00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
00000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

With option -a, the tool looks for string 00000000:.

Option -s can be used to select another hexadecimal/ASCII dump than the first one (for example, -s 2 to select the second dump).

Option -l (list) can be used to produce an overview of all hexadecimal/ASCII dumps found in the input, together with an index number to be used with option -s.

The binary data is written to standard output.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        sys.stdout.flush()
        data = data[10000:]

def FindBeginHEXASCIIDump(data):
    positions = []
    position = 0
    while position != -1:
        position = data.find('00000000: ', position)
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
    result = ''
    for line in data[positions[select - 1]:].split('\n'):
        line = line.strip()
        if len(line) <= positionColon:
            break
        if line[positionColon] == ':':
            result += line[positionColon + 2:positionColon + 2 + lengthHexadecimal] + '\n'
        else:
            break
    return result

def ListHEXASCIIDumps(data):
    for index, position in enumerate(FindBeginHEXASCIIDump(data)):
        print('%d: %s' % (index + 1, data[position:].split('\n')[0]))

def Hex2Bin(filename, options):
    FixPipe()
    if filename == '':
        content = sys.stdin.read()
    else:
        content = File2String(filename)
    if options.asciidump:
        content = ExtractHEXASCIIDump(content, int(options.select))
    elif options.list:
        ListHEXASCIIDumps(content)
        return
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    StdoutWriteChunked(binascii.unhexlify(content.replace(' ', '').replace('\t', '').replace('\r', '').replace('\n', '')))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='Extract Hex/ASCII dump from other tools')
    oParser.add_option('-l', '--list', action='store_true', default=False, help='List all Hex/ASCII dumps')
    oParser.add_option('-s', '--select', default='1', help='select dump nr for extraction (default first dump)')
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
