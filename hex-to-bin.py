#!/usr/bin/env python

__description__ = 'Hex to bin'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/01/06'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2015/12/20: added stdin support
  2016/01/06: changed name from hex2bin.py to hex-to-bin.py; added man

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

The binary data is written to standard output.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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

def Hex2Bin(filename, options):
    FixPipe()
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    if filename == '':
        content = sys.stdin.read()
    else:
        content = File2String(filename)
    StdoutWriteChunked(binascii.unhexlify(content.replace(' ', '').replace('\t', '').replace('\r', '').replace('\n', '')))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
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
