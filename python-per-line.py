#!/usr/bin/env python

__description__ = "Program to evaluate a Python expression for each line in the provided text file(s)"
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2018/02/05'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/05/14: start
  2017/04/23: refactoring, @ (stdin), Duckify, option -s
  2017/05/27: 0.0.2 added gzip support
  2017/06/04: Added RIN
  2017/06/05: Added SBC
  2017/06/11: added option -e
  2017/07/23: updated man
  2018/02/05: 0.0.3 added option -i

Todo:
"""

import optparse
import glob
import collections
import sys
import textwrap
import gzip
import os

def PrintManual():
    manual = '''
Manual:

This program reads lines from the given file(s) or standard input, and then evaluates the provided Python expression on each line of text and outputs the result of the Python expression.
If an input file is a gzip compressed file (extension .gz), this program will decompress its content to read the lines.

The Python expression needs to use {} or Python variable line to represent the content of each line. Before evaluation, {} is replaced by the content of each line surrounded by single quotes.
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

IFF is a predefined Python function that implements the if Function (IFF = IF Function). It takes three arguments: expression, valueTrue, valueFalse. If expression is true, then valueTrue is returned, otherwise valueFalse is returned.

RIN is a predefined Python function that uses the repr function if needed (RIN = Repr If Needed). When a string contains characters that need to be escaped to be used in Python source code, repr(string) is returned, otherwise the string itself is returned.

SBC is a predefined Python function that helps with selecting a value from lines with values and separators (Separator Based Cut = SBC). SBC takes five arguments: data, separator, columns, column, failvalue.
data is the data we want to parse (usually line), separator is the separator character, columns is the number of columns per line, column is the value we want to select (cut) starting from 0, and failvalue is the value that SBC needs to return if the function fails (for example because there are less columns in the line than specified by the columns value).
Here is an example. We use this file with credentials (creds.txt):
 username1:password
 username2
 username3:pass:word
 username4:

And this is the command to extract the passwords:
python-per-line.py "SBC(line, ':', 2, 1, [])" creds.txt

The result:
 password
 pass:word
 
If a line contains more separators than specified by the columns argument, then everything past the last expected separator is considered the last value (this includes the extra separator(s)). We can see this with line "username3:pass:word". The password is pass:word (not pass). SBC returns pass:word.
If a line contains less separators than specified by the columns argument, then the failvalue is returned. [] makes python-per-line skip an output line, that is why no output is produced for user2.

The lines are written to standard output, except when option -o is used. When option -o is used, the lines are written to the file specified by option -o.

An extra Python script (for example with custom definitions) can be loaded using option -s.

Option -e (execute) is used to execute Python commands before the command is executed. This can, for example, be used to import modules.

If an error occurs when the Python expression is evaluated, the program will report the error and stop. This behavior can be changed with option -i (ignore): using this option, no errors will be reported when evaluating the Python expression and the program will continue to run.
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

def RINSub(data, specialcharacters=''):
    if specialcharacters != '':
        for specialcharacter in specialcharacters:
            if specialcharacter in data:
                return repr(data)
        return data
    elif "'" + data + "'" == repr(data):
        return data
    else:
        return repr(data)

# RIN: Repr If Needed
def RIN(data, specialcharacters=''):
    if type(data) == list:
        return [RINSub(item, specialcharacters) for item in data]
    else:
        return RINSub(data, specialcharacters)

def Findall(data, separator):
    indices = []
    index = 0
    while index != -1:
        index = data.find(separator, index)
        if index != -1:
            indices.append(index)
            index += 1
    return indices

# SBC: Separator Based Cut
def SBC(data, separator, columns, column, failvalue):
    indices = Findall(data, separator)
    if len(indices) + 1 < columns:
        return failvalue
    if column == 0:
        return data[0:indices[0]]
    elif columns == column + 1:
        return data[indices[column - 1] + 1:]
    else:
        return data[indices[column - 1] + 1:indices[column]]

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
    if type(fIn) == list:
        for index in xrange(fIn[0], fIn[1], fIn[2]):
            yield str(index)
    elif fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n\r')

def Duckify(line):
    result = ['ENTER']
    if line !='':
        result[0:0] = ['STRING ' + line]
    return result

def PythonPerLineSingle(expression, filename, oOutput, options):
    if filename == '':
        fIn = sys.stdin
    elif type(filename) == list:
        fIn = filename
    elif os.path.splitext(filename)[1].lower() == '.gz':
        fIn = gzip.GzipFile(filename, 'rb')
    else:
        fIn = open(filename, 'r')
    for line in ProcessFile(fIn, False):
        expressionToEvaluate = expression.replace('{}', repr(line))
        try:
            result = eval(expressionToEvaluate)
        except:
            result = []
            if not options.ignore:
                raise
        if not isinstance(result, list):
            result = [result]
        for item in result:
            oOutput.Line(item)
    if fIn != sys.stdin and type(fIn) != list:
        fIn.close()

def ParseRange(data):
    values = data.split(',')
    if len(values) == 0 or len(values) > 3:
        raise Exception("Range option error")
    if len(values) == 1:
        return [0, int(values[0]), 1]
    elif len(values) == 2:
        return [int(values[0]), int(values[1]), 1]
    else:
        return [int(values[0]), int(values[1]), int(values[2])]

def PythonPerLine(expression, filenames, options):
    if options.execute != '':
        exec(options.execute, globals())

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
    oParser.add_option('-s', '--script', type=str, default='', help='Script with definitions to include')
    oParser.add_option('-e', '--execute', default='', help='Commands to execute')
    oParser.add_option('-r', '--range', type=str, default='', help='Parameters to generate input with xrange')
    oParser.add_option('-i', '--ignore', action='store_true', default=False, help='Ignore errors when evaluating the expression')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.range != '':
        PythonPerLine(args[0], [ParseRange(options.range)], options)
    elif len(args) == 0:
        oParser.print_help()
        return
    elif len(args) == 1:
        PythonPerLine(args[0], [''], options)
    else:
        PythonPerLine(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
