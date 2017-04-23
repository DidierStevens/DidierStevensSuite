#!/usr/bin/env python

__description__ = "Program to evaluate a Python expression for each line in the provided text file(s)"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/04/23'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/05/14: start
  2017/04/23: refactoring, @ (stdin), Duckify, option -s

Todo:
"""

import optparse
import glob
import collections
import sys
import textwrap

def PrintManual():
    manual = '''
Manual:

This program reads lines from the given file(s) or standard input, and then evaluates the provided Python expression on each line of text and outputs the result of the Python expression.

The Python expression needs to use {} to represent the content of each line. Before evaluation, {} is replaced by the content of each line surrounded by single quotes.
The value of the evaluated expression is outputed as a single line, except when the Pythion expression returns a list. In that case, each element of the list is outputed on a single line.

Example:
 Content test.txt:
 Line 1
 Line 2
 Line 3

 Command:
 python-per-line.py "'copy ' + {}" test.txt

 Output:
 copy Line 1
 copy Line 2
 copy Line 3

This program contains a predefined Python function to help with the generation of Rubber Ducky scripts: Duckify.

Example:
 Content test.txt:
 Line 1
 Line 2
 Line 3

 Command:
 python-per-line.py "Duckify({})" test.txt

 Output:
 STRING Line 1
 ENTER
 STRING Line 2
 ENTER
 STRING Line 3
 ENTER

The lines are written to standard output, except when option -o is used. When option -o is used, the lines are written to the file specified by option -o.

An extra Python script (for example with custom definitions) can be loaded using option -s.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
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
#            sys.stdout.flush()

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

def Duckify(line):
    result = ['ENTER']
    if line !='':
        result[0:0] = ['STRING ' + line]
    return result

def PythonPerLineSingle(expression, filename, oOutput, options):
    if filename == '':
        fIn = sys.stdin
    else:
        fIn = open(filename, 'r')
    for line in ProcessFile(fIn, False):
        result = eval(expression.replace('{}', "'" + line + "'"))
        if not isinstance(result, list):
            result = [result]
        for item in result:
            oOutput.Line(item)
    if fIn != sys.stdin:
        fIn.close()

def PythonPerLine(expression, filenames, options):
    if options.script != '':
        execfile(options.script, globals(), globals())
    oOutput = cOutputResult(options)
    for filename in filenames:
        PythonPerLineSingle(expression, filename, oOutput, options)
    oOutput.Close()

def Main():
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
    oParser.add_option('-s', '--script', default='', help='Script with definitions to include')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
        return
    if len(args) == 1:
        PythonPerLine(args[0], [''], options)
    else:
        PythonPerLine(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
