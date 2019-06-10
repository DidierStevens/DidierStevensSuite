#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Set operations on 2 (or 1) files: union, intersection, subtraction, exclusive or, sample, join, unique, product, substitute, sort'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2018/12/30'

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
  2018/07/17: added operation join
  2018/09/09: 0.0.3 added options -i -s operation unique
  2018/09/12: refactoring
  2018/12/30: added operations product, substitute, sort

Todo:
"""

import optparse
import sys
import binascii
import textwrap
import random
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO

OPERATION_UNION = 'union'
OPERATION_INTERSECT = 'intersect'
OPERATION_SUBTRACT = 'subtract'
OPERATION_XOR = 'xor'
OPERATION_SAMPLE = 'sample'
OPERATION_JOIN = 'join'
OPERATION_UNIQUE = 'unique'
OPERATION_PRODUCT = 'product'
OPERATION_SUBSTITUTE = 'substitute'
OPERATION_SORT = 'sort'

def PrintManual():
    manual = '''
Manual:

This program performs set operations on text files. The elements of the set are the lines of the files.
Mathematically speaking, inputs don't have to be sets anymore. For example, operation unique takes a list as input and produces a set.

This Python script was developed with Python 2.7 and tested with Python 2.7 and 3.5.

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

Content of file set3.txt:
 Line 1
 Line 2
 Line 3
 Line 4
 Line 5
 Line 6
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

Example to create a unique set of file set3.txt:
 sets.py set3.txt unique
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

Example to join the elements of file set1.txt into one string separated by _x_ (without newlines):
 sets.py set1.txt join _x_
Output:
 Line 1_x_Line 2_x_Line 3_x_Line 4_x_Line 5_x_Line 6

Example to make the product of files set1.txt and set2.txt:
 sets.py set1.txt product set2.txt
Output:
 Line 1Line 4
 Line 2Line 4
 Line 3Line 4
 Line 4Line 4
 Line 5Line 4
 Line 6Line 4
 Line 1Line 5
 Line 2Line 5
 Line 3Line 5
 Line 4Line 5
 Line 5Line 5
 Line 6Line 5
 Line 1Line 6
 Line 2Line 6
 Line 3Line 6
 Line 4Line 6
 Line 5Line 6
 Line 6Line 6
 Line 1Line 7
 Line 2Line 7
 Line 3Line 7
 Line 4Line 7
 Line 5Line 7
 Line 6Line 7
 Line 1Line 8
 Line 2Line 8
 Line 3Line 8
 Line 4Line 8
 Line 5Line 8
 Line 6Line 8
 Line 1Line 9
 Line 2Line 9
 Line 3Line 9
 Line 4Line 9
 Line 5Line 9
 Line 6Line 9

Example to make the product of files set1.txt and set2.txt with a template:
 sets.py -t "@1@ -> @2@" set1.txt product set2.txt
Output:
 Line 1 -> Line 4
 Line 2 -> Line 4
 Line 3 -> Line 4
 Line 4 -> Line 4
 Line 5 -> Line 4
 Line 6 -> Line 4
 Line 1 -> Line 5
 Line 2 -> Line 5
 Line 3 -> Line 5
 Line 4 -> Line 5
 Line 5 -> Line 5
 Line 6 -> Line 5
 Line 1 -> Line 6
 Line 2 -> Line 6
 Line 3 -> Line 6
 Line 4 -> Line 6
 Line 5 -> Line 6
 Line 6 -> Line 6
 Line 1 -> Line 7
 Line 2 -> Line 7
 Line 3 -> Line 7
 Line 4 -> Line 7
 Line 5 -> Line 7
 Line 6 -> Line 7
 Line 1 -> Line 8
 Line 2 -> Line 8
 Line 3 -> Line 8
 Line 4 -> Line 8
 Line 5 -> Line 8
 Line 6 -> Line 8
 Line 1 -> Line 9
 Line 2 -> Line 9
 Line 3 -> Line 9
 Line 4 -> Line 9
 Line 5 -> Line 9
 Line 6 -> Line 9

Example to sort the set in file set3.txt:
 sets.py set3.txt sort
Output:
 Line 1
 Line 2
 Line 3
 Line 4
 Line 4
 Line 5
 Line 5
 Line 6
 Line 6
 Line 7
 Line 8
 Line 9

Use option -i to make the comparison of elements not case sensitive.
Use option -s to strip the elements (remove leading and trailing whitespace) when comparing.

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

    def String(self, string):
        if self.f:
            self.f.write(string)
        else:
            print(string, end='')

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
                f = StringIO(decoded)
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
            lines = [x.strip('\n\r') for x in f.readlines()]
        except:
            return None
        finally:
            if filename != '':
                f.close()
    return lines

def Intersect(set1, set2, ignorecase, strip):
    if not ignorecase and not strip:
        return [line for line in set1 if line in set2]
    if ignorecase and strip:
        Function = lambda str: str.lower().strip()
    if ignorecase and not strip:
        Function = lambda str: str.lower()
    if not ignorecase and strip:
        Function = lambda str: str.strip()
    return [line for line in set1 if Function(line) in [Function(line2) for line2 in set2]]

def Subtract(set1, set2, ignorecase, strip):
    if not ignorecase and not strip:
        return [line for line in set1 if not line in set2]
    if ignorecase and strip:
        Function = lambda str: str.lower().strip()
    if ignorecase and not strip:
        Function = lambda str: str.lower()
    if not ignorecase and strip:
        Function = lambda str: str.strip()
    return [line for line in set1 if not Function(line) in [Function(line2) for line2 in set2]]

def Sample(set1, k):
    random.seed()
    return random.sample(set1, k)

def Join(set1, separator):
    return separator.join(set1)

def Unique(set1, ignorecase, strip):
    dUniques = {}
    result = []
    if not ignorecase and not strip:
        Function = lambda str: str
    if ignorecase and strip:
        Function = lambda str: str.lower().strip()
    if ignorecase and not strip:
        Function = lambda str: str.lower()
    if not ignorecase and strip:
        Function = lambda str: str.strip()
    for line in set1:
        if not Function(line) in dUniques:
            result.append(line)
            dUniques[Function(line)] = True
    return result

def Product(set1, set2, template):
    if template == '':
        template = '@1@@2@'
    return [template.replace('@1@', line1).replace('@2@', line2) for line2 in set2 for line1 in set1]

def Substitute(set, template):
    return [template.replace('@@', line) for line in set]

def Sort(set, ignorecase, strip):
    if ignorecase and strip:
        keyarg = lambda a: a.lower().strip()
    elif ignorecase:
        keyarg = str.lower
    elif strip:
        keyarg = str.strip
    else:
        keyarg = None
    return sorted(set, key=keyarg)

def SetOperation(file1, operation, file2, options):
    content1 = File2List(file1, options.bytemode)
    if not operation in [OPERATION_SAMPLE, OPERATION_JOIN, OPERATION_UNIQUE, OPERATION_SUBSTITUTE, OPERATION_SORT]:
        content2 = File2List(file2, options.bytemode)
    if operation == OPERATION_UNION:
        result = content1 + Subtract(content2, content1, options.ignorecase, options.strip)
    elif operation == OPERATION_INTERSECT:
        result = Intersect(content1, content2, options.ignorecase, options.strip)
    elif operation == OPERATION_SUBTRACT:
        result = Subtract(content1, content2, options.ignorecase, options.strip)
    elif operation == OPERATION_XOR:
        result = Subtract(content1, content2, options.ignorecase, options.strip) + Subtract(content2, content1, options.ignorecase, options.strip)
    elif operation == OPERATION_SAMPLE:
        result = Sample(content1, int(file2))
    elif operation == OPERATION_JOIN:
        result = Join(content1, file2)
    elif operation == OPERATION_UNIQUE:
        result = Unique(content1, options.ignorecase, options.strip)
    elif operation == OPERATION_PRODUCT:
        result = Product(content1, content2, options.template)
    elif operation == OPERATION_SUBSTITUTE:
        result = Substitute(content1, file2)
    elif operation == OPERATION_SORT:
        result = Sort(content1, options.ignorecase, options.strip)
    else:
        print('Unknown operation: %s' % operation)
        return
    oOutput = cOutput(options.output)
    if options.bytemode:
        oOutput.Line(''.join(result))
    elif operation == OPERATION_JOIN:
        oOutput.String(result)
    else:
        for line in result:
            oOutput.Line(line)
    oOutput.Close()

def Main():
    operations = '|'.join([OPERATION_UNION, OPERATION_INTERSECT, OPERATION_SUBTRACT, OPERATION_XOR, OPERATION_SAMPLE, OPERATION_JOIN, OPERATION_UNIQUE, OPERATION_PRODUCT, OPERATION_SUBSTITUTE, OPERATION_SORT])
    oParser = optparse.OptionParser(usage='usage: %prog [options] ' + operations + ' [file2]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', default='', help='Output file')
    oParser.add_option('-b', '--bytemode', action='store_true', default=False, help='byte mode')
    oParser.add_option('-i', '--ignorecase', action='store_true', default=False, help='ignore case when comparing elements')
    oParser.add_option('-s', '--strip', action='store_true', default=False, help='strip elements when comparing')
    oParser.add_option('-t', '--template', default='', help='Template for operations like product (@1@, @2@, @@)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 1 and args[0] in [OPERATION_UNIQUE, OPERATION_SORT]:
        SetOperation('', args[0], None, options)
    elif len(args) != 2 and len(args) != 3:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 2 and args[1] in [OPERATION_UNIQUE, OPERATION_SORT]:
        SetOperation(args[0], args[1], None, options)
    elif len(args) == 2:
        SetOperation('', args[0], args[1], options)
    else:
        SetOperation(args[0], args[1], args[2], options)

if __name__ == '__main__':
    Main()
