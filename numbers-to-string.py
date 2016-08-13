#!/usr/bin/env python

__description__ = "Program to convert numbers into a string"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/11/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/11/02: start
  2015/11/12: added import math

Todo:
"""

import optparse
import glob
import collections
import re
import sys
import textwrap
import math

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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
            yield line.strip('\n')

def NumbersToStringSingle(function, filenames, oOutput, options):
    if function == "":
        Function = lambda x: x
    else:
        Function = eval(function)
    oRE = re.compile('\d+')
    for filename in filenames:
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        for line in ProcessFile(fIn, False):
            results = oRE.findall(line)
            if len(results) >= options.number:
                error = True
                try:
                    result = ''.join(map(chr, Function(map(int, results))))
                    error = False
                except:
                    if options.error:
                        raise
                if not error:
                    oOutput.Line(result)
        if fIn != sys.stdin:
            fIn.close()

def NumbersToString(function, filenames, options):
    oOutput = cOutputResult(options)
    NumbersToStringSingle(function, filenames, oOutput, options)
    oOutput.Close()

def Main():
    global dLibrary

    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] expression [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-e', '--error', action='store_true', default=False, help='Generate error when error occurs in Python expression')
    oParser.add_option('-n', '--number', type=int, default=3, help='Minimum number of numbers (3 by default)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
    elif len(args) == 1:
        NumbersToString(args[0], [''], options)
    else:
        NumbersToString(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
