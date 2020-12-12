#!/usr/bin/env python

__description__ = "Program to convert numbers into a string"
__author__ = 'Didier Stevens'
__version__ = '0.0.11'
__date__ = '2020/12/10'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/11/02: start
  2015/11/12: added import math
  2016/09/10: added option -j
  2017/08/11: 0.0.2 added option -i
  2017/11/10: 0.0.3 added man page
  2018/06/29: 0.0.4 added options --grep and --grepoptions
  2018/07/25: added options --begin and --end
  2018/07/25: updated man
  2018/08/25: 0.0.5 added option -S
  2018/12/15: 0.0.6 added option -t and changed option --end
  2018/12/15: 0.0.7 added option -T
  2019/09/25: 0.0.8 added option -b
  2019/11/02: added C2BIP3
  2019/12/08: 0.0.9 Python 3 bug fix
  2020/08/16: 0.0.10 added option -v
  2020/12/10: 0.0.11 Python 3 bug fix, added option -l

Todo:
"""

import optparse
import glob
import collections
import re
import sys
import textwrap
import math
import os

def PrintManual():
    manual = '''
Manual:

numbers-to-string.py is a Python program that reads texts files (as arguments on the commandline, @here files or stdin), extract numbers from these files and converts these to strings.
The first argument of numbers-to-string.py is a Python expression. This Python expression can use variable n that represents each extracted number.

Here is an example, with a script file (test.js) containing a list of numbers:

C:\Demo>type test.js
a = (68, 105, 100, 105, 101, 114)

Running this script file through numbers-to-string.py with an empty expression ("") converts the numbers to a string:

C:\Demo>numbers-to-string.py "" test.js
Didier

68 is the ASCII number of letter D, 105 is the ASCII number of letter i, ...
numbers-to-string.py converts each number it extracts to a character, and concatenates them into one string per line.

The same result can be obtained by using Python expression n, where n represents the extracted numbers:

C:\Demo>numbers-to-string.py n test.js
Didier

The advantage of using a Python expression becomes obvious when the numbers have been altered to obfuscate their meaning.

In the next example, 1 has been added to each number, making straightforward conversion generate an unintelligible string:

a = (105, 117, 117, 113, 116, 59, 48, 48, 69, 106, 101, 106, 102, 115, 84, 117, 102, 119, 102, 111, 116, 47, 100, 112, 110)

C:\Demo>numbers-to-string.py n test.js
iuuqt;00EjejfsTufwfot/dpn

If we use the Python expression to substract 1 from each number (n - 1), then we can decode the string:

C:\Demo>numbers-to-string.py "n - 1" test.js
https://DidierStevens.com

For more complex operations, a lambda expression can be used. The argument of the lambda expression is the list of numbers.
Here is an example from a real malicious document:

C:\Demo>numbers-to-string.py "lambda l: [b - 40 + i*2 for i, b in enumerate(l)]" test.js
http://pmspotter.wz.cz/656465/d5678h9.exe

numbers-to-string.py will work line per line, as illustrated with this example:

C:\Demo>type test.js
a = (68, 105, 100, 105, 101, 114)
b = (83, 116, 101, 118, 101, 110, 115)

C:\Demo>numbers-to-string.py n test.js
Didier
Stevens

With option -j, the output strings can be concatenated:

C:\Demo>numbers-to-string.py -j n test.js
DidierStevens

numbers-to-string translates numbers into characters according to the ASCII table. You can use another table (index starting at zero), by using option -t and providing a string with the character sequence needed for proper decoding:

C:\Demo>echo "3,1,2,2,4" | numbers-to-string.py -t "xelHo"
Hello

If the string for the translation is contained in the line with numbers, you can use option -T ... to extract the translation string by replacing ... with the start of the translation string.

numbers-to-string.py can also generate statistics, to help with the identification of the encoding. Use option -S to generate statistics, like this:

C:\Demo>numbers-to-string.py -S test.js
Line      1: count =     25 minimum =     47 maximum =    119 average =     97
Total      : count =     25 minimum =     47 maximum =    119 average =     97

Output can be written to a file using option -o.

Use option -b --binary when you expect the output to be binary data. This option will prevent linefeeds to be expanded to carriage return + linefeed on Windows (this tool produces text output by default).

numbers-to-string.py needs at least 3 numbers per line to start extracting. Lines with less than 3 numbers are ignored. 3 numbers is the default minimum value, and can be changed using option -n.

Use option -v --verbose to get more insight into the data processing done by this tool.

Errors that occur when evaluating the Python expression will be silently ignored. To have the tool raise these errors, use option -e.

If the resulting value of the expression is more than 255, an error will be generated, unless option -i is used to ignore these errors.

Option --grep can be used to select (grep) lines that have to be processed.
If this option is not used, all lines will be processed.
To select particular lines to be processed, used option --grep and provide a regular expression. All lines matching this regular expression will be processed.
You can also use a capture group in your regular expression. The line to be processed will become the content of the first capture group (and not the complete line).
The regular expression matching operation is case sensitive. Use option --grepoptions i to make the matching operation case insensitive.
Use option --grepoptions v to invert the selection.
Use option --grepoptions F to match a fixed string in stead of a regular expression.

Option --begin can be used to provide the string that is the start of number processing per line.
Option --end can be used to provide the string (last occurence) that is the end of number processing per line.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(C2BIP3(data))
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

class cOutput():
    def __init__(self, filename=None, binary=False):
        self.filename = filename
        self.binary = binary
        if self.filename and self.filename != '':
            self.f = open(self.filename, IFF(self.binary, 'wb', 'w'))
        else:
            self.f = None
            if self.binary:
                IfWIN32SetBinary(sys.stdout)

    def Line(self, line):
        if self.f:
            if self.binary:
                self.f.write(line)
            else:
                self.f.write(line + '\n')
        else:
            if self.binary:
                StdoutWriteChunked(line)
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
            self.oOutput = cOutput(options.output, options.binary)
        else:
            self.oOutput = cOutput(binary=options.binary)
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
            yield line.strip('\n\r')

class cGrep():
    def __init__(self, expression, options):
        self.expression = expression
        self.options = options
        if self.expression == '' and self.options != '':
            raise Exception('Option --grepoptions can not be used without option --grep')
        self.dogrep = self.expression != ''
        self.oRE = None
        self.invert = False
        self.caseinsensitive = False
        self.fixedstring = False
        if self.dogrep:
            flags = 0
            for option in self.options:
                if option == 'i':
                    flags = re.IGNORECASE
                    self.caseinsensitive = True
                elif option == 'v':
                    self.invert = True
                elif option == 'F':
                    self.fixedstring = True
                else:
                    raise Exception('Unknown grep option: %s' % option)
            self.oRE = re.compile(self.expression, flags)

    def Grep(self, line):
        if self.fixedstring:
            if self.caseinsensitive:
                found = self.expression.lower() in line.lower()
            else:
                found = self.expression in line
            if self.invert:
                return not found, line
            else:
                return found, line
        else:
            oMatch = self.oRE.search(line)
            if self.invert:
                return oMatch == None, line
            if oMatch != None and len(oMatch.groups()) > 0:
                line = oMatch.groups()[0]
            return oMatch != None, line

def CalculateStatistics(numbers):
    numbers = list(map(int, numbers))
    return (len(numbers), min(numbers), max(numbers), sum(numbers) / len(numbers))

def Chr(number, options, translation):
    number = int(number)
    try:
        if options.table != '':
            return options.table[number]
        elif options.begintable != '':
            return translation[number]
        else:
            return chr(number)
    except:
        if options.ignore:
            return ''
        else:
            raise

def NumbersToStringSingle(function, filenames, oOutput, options):
    oGrep = cGrep(options.grep, options.grepoptions)
    if function == '':
        Function = lambda x: x
    elif function.startswith('lambda '):
        Function = eval(function)
    else:
        Function = None
    oRE = re.compile('\d+')
    for filename in filenames:
        joined = ''
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        if options.statistics:
            linecounter = 1
            totalResults = []
            for line in ProcessFile(fIn, False):
                results = oRE.findall(line)
                totalResults += results
                if results != []:
                    oOutput.Line('Line %6d: count = %6d minimum = %6d maximum = %6d average = %6d' % ((linecounter, ) + CalculateStatistics(results)))
                linecounter += 1
            if totalResults != []:
                oOutput.Line('Total      : count = %6d minimum = %6d maximum = %6d average = %6d' % CalculateStatistics(totalResults))
        else:
            for index, line in enumerate(ProcessFile(fIn, False)):
                selected = True
                if oGrep.dogrep:
                    selected, line = oGrep.Grep(line)
                if not selected:
                    continue
                translation = ''
                if options.begintable != '':
                    position = line.find(options.begintable)
                    if position == -1:
                        continue
                    translation = line[position:]
                if options.begin != '':
                    position = line.find(options.begin)
                    if position == -1:
                        continue
                    line = line[position:]
                if options.end != '':
                    position = line.rfind(options.end)
                    if position == -1:
                        continue
                    line = line[:position + len(options.end)]
                results = oRE.findall(line)
                if options.line == '' and len(results) >= options.number or options.line == str(index + 1):
                    if options.verbose:
                        oOutput.Line('Line number: %d' % (index + 1))
                        oOutput.Line('Line: %s' % line)
                        oOutput.Line('%d numbers: %s' % (len(results), repr(results)))
                        oOutput.Line('Decoded:')
                    ChrFunction = lambda c: Chr(c, options, translation)
                    error = True
                    if Function == None:
                        try:
                            result = ''.join(map(ChrFunction, [eval(function) for n in map(int, results)]))
                            error = False
                        except:
                            raise
                            if options.error:
                                print('n = %d' % n)
                                raise
                    else:
                        try:
                            result = ''.join(map(ChrFunction, Function(map(int, results))))
                            error = False
                        except:
                            if options.error:
                                raise
                    if not error:
                        if options.join:
                            joined += result
                        else:
                            oOutput.Line(result)
            if options.join:
                oOutput.Line(joined)
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

    oParser = optparse.OptionParser(usage='usage: %prog [options] [expression [[@]file ...]]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-e', '--error', action='store_true', default=False, help='Generate error when error occurs in Python expression')
    oParser.add_option('-i', '--ignore', action='store_true', default=False, help='Ignore numbers greater than 255')
    oParser.add_option('-n', '--number', type=int, default=3, help='Minimum number of numbers (3 by default)')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='Verbose')
    oParser.add_option('-j', '--join', action='store_true', default=False, help='Join output')
    oParser.add_option('-S', '--statistics', action='store_true', default=False, help='Generate statistics')
    oParser.add_option('-t', '--table', type=str, default='', help='Translation table')
    oParser.add_option('-T', '--begintable', type=str, default='', help='Begin translation table')
    oParser.add_option('-b', '--binary', action='store_true', default=False, help='Produce binary output')
    oParser.add_option('-l', '--line', type=str, default='', help='Select line with given number')
    oParser.add_option('--grep', type=str, default='', help='Grep expression')
    oParser.add_option('--grepoptions', type=str, default='', help='Grep options')
    oParser.add_option('--begin', type=str, default='', help='Begin substring')
    oParser.add_option('--end', type=str, default='', help='End substring')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.statistics and options.binary:
        print('Options statistics and binary are mutually exclusive!')
        return
    if len(args) == 0:
        NumbersToString('', [''], options)
    elif len(args) == 1 and not options.statistics:
        NumbersToString(args[0], [''], options)
    elif options.statistics:
        NumbersToString('', ExpandFilenameArguments(args), options)
    else:
        NumbersToString(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
