#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Split file with overlap'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/12/28'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/12/11: start
  2021/12/28: continue
"""

import optparse
import textwrap

def PrintManual():
    manual = '''
Manual:

This tool reads a binary file and splits it in parts of equal length.

Example:

split-overlap.py 1000 test.data

test.data is a binary file of 2500 bytes.

The tool will create 3 files:
test.data.01.bin -> first 1000 bytes of test.data
test.data.02.bin -> next 1000 bytes of test.data
test.data.03.bin -> remaining 500 bytes of test.data

The first argument is the size the parts: an integer, that can have K, M or G as suffix (not case-sensitive). K stands for Kilobyte, M for Megabyte, G for Gigabyte.

It is also possible to generates file parts with an overlap. The size of the overlap is provided as follows: length+overlap.

Example: 99M+1M -> this will create file parts of 100Mb in size, with a 1MB overlap.

Let's illustrate with file letters.data that contains the 26 letters of the alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ.

Command "split-overlap.py 10 letters.data" will create 3 files with the following content:

letters.data.01.bin -> ABCDEFGHIJ
letters.data.02.bin -> KLMNOPQRST
letters.data.03.bin -> UVWXYZ

With an overlap of 1 byte, the result is the following:

Command "split-overlap.py 9+1 letters.data" will create 3 files with the following content:

letters.data.01.bin -> ABCDEFGHIJ
letters.data.02.bin -> JKLMNOPQRS
letters.data.03.bin -> STUVWXYZ

The last byte of each part is used as the first byte of the next part.

This example with 1 byte overlap is for illustration reasons, the overlap can be any size (has to be smaller than the length).

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def EndsWithGetRemainder(strIn, strEnd):
    if strIn.endswith(strEnd):
        return True, strIn[:-len(strEnd)]
    else:
        return False, None

def ParseSplitValue(expression):
    expression = expression.lower()
    found, remainder = EndsWithGetRemainder(expression, 'g')
    if found:
        return int(remainder) * 1024 * 1024 * 1024
    found, remainder = EndsWithGetRemainder(expression, 'm')
    if found:
        return int(remainder) * 1024 * 1024
    found, remainder = EndsWithGetRemainder(expression, 'k')
    if found:
        return int(remainder) * 1024
    return int(expression)

def SplitOverlap(splitexpression, filename, options):
    result = [ParseSplitValue(part) for part in splitexpression.split('+')]
    if len(result) == 1:
        length = result[0]
        overlap = 0
    elif len(result) == 2:
        length = result[0]
        overlap = result[1]
    else:
        raise Exception('Unexpected split expression: %s' % splitexpression)

    counter = 1
    with open(filename, 'rb') as fIn:
        while True:
            if counter == 1:
                data = fIn.read(length + overlap)
                dataOverlap = b''
            else:
                if overlap == 0:
                    dataOverlap = b''
                else:
                    dataOverlap = data[-overlap:]
                data = fIn.read(length)
            if len(data) == 0:
                break
            with open('%s.%02d.bin' % (filename, counter), 'wb') as fOut:
                fOut.write(dataOverlap + data)
            counter += 1

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] length[+overlap] file\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    SplitOverlap(args[0], args[1], options)

if __name__ == '__main__':
    Main()
