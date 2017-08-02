#!/usr/bin/env python

__description__ = 'Set operations on 2 files: union, intersection, subtraction, exclusive or, sample'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2017/08/02'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/07/29: start
  2015/07/08: added stdin input
  2017/03/01: added # filename and option -b
  2017/03/03: added man
  2017/08/02: 0.0.2: added operation sample

Todo:
"""

import optparse
import sys
import binascii
import StringIO
import textwrap
import random

def PrintManual():
    manual = '''
Manual:

This program performs set operations on text files. The elements of the set are the lines of the files.

Content of file set1.txt:
 Line 1
 Line 2
 Line 3
 Line 4
 Line 5
 Line 6

Content of file set2.txt:
 Line 4
 Line 5
 Line 6
 Line 7
 Line 8
 Line 9

Example to make the union for files set1.txt and set2.txt:
 sets.py set1.txt union set2.txt
Output:
 Line 1
 Line 2
 Line 3
 Line 4
 Line 5
 Line 6
 Line 7
 Line 8
 Line 9

Example to make the intersection for files set1.txt and set2.txt:
 sets.py set1.txt intersect set2.txt
Output:
 Line 4
 Line 5
 Line 6

Example to subtract file set2.txt from file set1.txt:
 sets.py set1.txt subtract set2.txt
Output:
 Line 1
 Line 2
 Line 3

Example to make the exclusive or for files set1.txt and set2.txt:
 sets.py set1.txt xor set2.txt
Output:
 Line 1
 Line 2
 Line 3
 Line 7
 Line 8
 Line 9

Example to select a random subset of 3 elements of file set1.txt:
 sets.py set1.txt sample 3
Output:
 Line 3
 Line 4
 Line 5

This program can also work on bytes/characters in stead of lines. This is done with option -b.

Content of file set1-bytes.txt:
 abcdef

Content of file set2-bytes.txt:
 defghi

Example:
 sets.py -b set1-bytes.txt intersect set2-bytes.txt
Output:
 def

Output can be written to a file with option -o.

The first file can be piped into the program via stdin.

In stead of putting the plaintext or the ciphertext in a file, it can also be passed in the argument. To achieve this, precede the text with character # (this is what we have done in all the examples up till now).
If the text to pass via the argument contains control characters or non-printable characters, hexadecimal (#h#) or base64 (#b#) can be used.

Example:
 sets.py -b #123456 xor #456789
Output:
 123789

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def FilenameCheckHash(filename):
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
    else:
        return ''

def File2List(filename, bytemode):
    try:
        if filename == '':
            f = sys.stdin
        else:
		        decoded = FilenameCheckHash(filename)
		        if decoded == '':
		            f = open(filename, 'r')
		        elif decoded == None:
		            print('Error parsing filename: ' + filename)
		            return
		        else:
		            f = StringIO.StringIO(decoded)
    except:
        return None
    if bytemode:
		    try:
		        lines = [b for b in f.read()]
		    except:
		        return None
		    finally:
		        if filename != '':
		            f.close()
    else:
		    try:
		        lines = [x.strip('\n') for x in f.readlines()]
		    except:
		        return None
		    finally:
		        if filename != '':
		            f.close()
    return lines

def Intersect(set1, set2):
    return [line for line in set1 if line in set2]

def Subtract(set1, set2):
    return [line for line in set1 if not line in set2]

def Sample(set1, k):
    random.seed()
    return random.sample(set1, k)

def SetOperation(file1, operation, file2, options):
    content1 = File2List(file1, options.bytemode)
    if operation != 'sample':
        content2 = File2List(file2, options.bytemode)
    if operation == 'union':
        result = content1 + Subtract(content2, content1)
    elif operation == 'intersect':
        result = Intersect(content1, content2)
    elif operation == 'subtract':
        result = Subtract(content1, content2)
    elif operation == 'xor':
        result = Subtract(content1, content2) + Subtract(content2, content1)
    elif operation == 'sample':
        result = Sample(content1, int(file2))
    else:
        print('Unknown operation: %s' % operation)
        return
    oOutput = cOutput(options.output)
    if options.bytemode:
        oOutput.Line(''.join(result))
    else:
        for line in result:
            oOutput.Line(line)
    oOutput.Close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file1] union|intersect|subtract|xor|sample file2\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', default='', help='Output file')
    oParser.add_option('-b', '--bytemode', action='store_true', default=False, help='byte mode')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 2 and len(args) != 3:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 2:
        SetOperation('', args[0], args[1], options)
    else:
        SetOperation(args[0], args[1], args[2], options)

if __name__ == '__main__':
    Main()
