#!/usr/bin/env python

__description__ = "Program to evaluate a Python expression for each line in the provided text file(s)"
__author__ = 'Didier Stevens'
__version__ = '0.0.12'
__date__ = '2024/06/15'

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
  2018/04/01: 0.0.4 added support for # to option -o
  2018/04/17: refactored support for # to option -o
  2018/04/22: updated man page with -r option
  2018/07/21: 0.0.5 added options --grep and --grepoptions
  2018/07/28: added options --begingrep, --begingrepoptions, --endgrep, and --endgrepoptions
  2019/03/20: 0.0.6 added option -n and libraries
  2019/04/20: added import binascii
  2020/03/02: 0.0.7 added option --encoding
  2020/04/19: updated man page
  2022/06/06: 0.0.8 added option -l, fixed xrange for Python 3
  2022/12/03: 0.0.9 added lineNumber
  2023/03/25: 0.0.10 added options --regex --split --join and Reverse* functions
  2023/04/08: 0.0.11 added option --group
  2024/06/15: 0.0.12 added cEnumeration; cStartsWithGetRemainder

Todo:
"""

import optparse
import glob
import collections
import sys
import textwrap
import gzip
import os
import time
import re
import binascii

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

Variable lineNumber is set to the line number of each selected line (first line -> lineNumber = 1).

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

Reverse is a function to reverse strings. It takes parameters string, group and shift.
Optional parameter group (with default value 1) specifies how many characters should be grouped before reversal. By default (value 1), each character is reversed individually (same as [::1]).
Example grouping by 2:

 Content test.txt:
 om.cnsveterSieid/D:/tpht

 Command:
 python-per-line.py "Reverse(line, 2)" test.txt

 Output:
 http://DidierStevens.com

Optional parameter shift (with default value 0) is used when the length of the string is not a multiple of the group value.

ReverseFind is a function to brute-force reverse strings to find substrings. Substrings are specified via optional argument search (default value ['http://', 'https://', 'ftp://']).
Example:

 Content test.txt:
 om.cnsveterSieid/D:/tpht

 Command:
 python-per-line.py "ReverseFind(line)" test.txt

 Output:
 http://DidierStevens.com

Use option -j to join all lines together, with or without a separator.
Without a separator: -j ""
With separator ;: -j ";"

Use option -R for regular expression matching. Only lines that match the regular expression will be processed, and the result of the regex match is available in variable oMatch.

Option -n is used when you just want to invoke a single Python function taking one argument (i.e. the line of text). Then you just have to provide the name of the Python function, and not a Python expression where this Python function is called with line as argument.

Like option -n, option -O is used to invoke a single Python function taking one argument, but this time the argument is an object in stead of a string. The object has several properties: item is the line (string), left is the previous line, right is the next line, index is equal to the line counter - 1.

Option -g is used to group all selected lines into Python variable "lines". The provided expression is not evaluated per line, but evaluated after each file has been read an its lines have been stored into Python variable "lines".

Option -r is used to generated a list of numbers and use that as input, in stead of a file.
This option accepts 1 to 3 numbers (separeted by a comma (,)), which are used as arguments to Python function xrange.
If just one number is given, then xrange is used with values (0, number, 1).
Example:
 python-per-line.py -r 10 "'Number ' + line"
 Number 0
 Number 1
 Number 2
 Number 3
 Number 4
 Number 5
 Number 6
 Number 7
 Number 8
 Number 9

Also here, variable line is a string.

If two numbers are given, then xrange is used with values (number1, number2, 1).
Example:
 python-per-line.py -r 5,10 "'Number ' + line"
 Number 5
 Number 6
 Number 7
 Number 8
 Number 9

If three numbers are given, then xrange is used with values (number1, number2, number3).
Example:
 python-per-line.py -r 5,10,2 "'Number ' + line"
 Number 5
 Number 7
 Number 9

Option -l is used to provide a list of lines (comma separated) and use that as input, in stead of a file.
Example:
 python-per-line.py -l Python,Lisp,C "line + '!'"
 Python!
 Lisp!
 C!

Option --grep can be used to select (grep) lines that have to be processed.
If this option is not used, all lines will be processed.
To select particular lines to be processed, used option --grep and provide a regular expression. All lines matching this regular expression will be processed.
You can also use a capture group in your regular expression. The line to be processed will become the content of the first capture group (and not the complete line).
The regular expression matching operation is case sensitive. Use option --grepoptions i to make the matching operation case insensitive.
Use option --grepoptions v to invert the selection.
Use option --grepoptions F to match a fixed string in stead of a regular expression.

Option --begingrep can be used to select the first line from which on lines have to be processed.
If this option is not used, all lines will be processed.
To select the first line to be processed, used option --begingrep and provide a regular expression. The line matching this regular expression and all following lines will be processed (depending on --grep and --endgrep).
The regular expression matching operation is case sensitive. Use option --begingrepoptions i to make the matching operation case insensitive.
Use option --begingrepoptions v to invert the selection.
Use option --begingrepoptions F to match a fixed string in stead of a regular expression.

Option --endgrep can be used to select the last line to be processed.
If this option is not used, all lines will be processed.
To select the last line to be processed, used option --endgrep and provide a regular expression. The line matching this regular expression will be the last line to be processed (depending on --grep).
The regular expression matching operation is case sensitive. Use option --endgrepoptions i to make the matching operation case insensitive.
Use option --endgrepoptions v to invert the selection.
Use option --endgrepoptions F to match a fixed string in stead of a regular expression.

When combining --begingrep and --endgrep, make sure that --endgrep does not match a line before --begingrep does.

Option --split can be used to split lines according to a given separator (one or more characters).

The lines are written to standard output, except when option -o is used. When option -o is used, the lines are written to the filename specified by option -o.
Filenames used with option -o starting with # have special meaning.
#c#example.txt will write output both to the console (stdout) and file example.txt.
#g# will write output to a file with a filename generated by the tool like this: toolname-date-time.log.
#g#KEYWORD will write output to a file with a filename generated by the tool like this: toolname-KEYWORD-date-time.log.
Use #p#filename to display execution progress.
To process several files while creating seperate output files for each input file, use -o #s#%f%.result *.
This will create output files with the name of the inputfile and extension .result.
There are several variables available when creating separate output files:
 %f% is the full filename (with directory if present)
 %b% is the base name: the filename without directory
 %d% is the directory
 %r% is the root: the filename without extension
 %e% is the extension
Most options can be combined, like #ps# for example.
#l# is used for literal filenames: if the output filename has to start with # (#example.txt for example), use filename #l##example.txt for example.

An extra Python script (for example with custom definitions) can be loaded using option -s.

Custom definitions can also be placed in a file named python-per-line.library in the same directory as the program is located, and/or in the current working directory. When present, these 2 files will be loaded upon each execution of the program.

Option -e (execute) is used to execute Python commands before the command is executed. This can, for example, be used to import modules.

If an error occurs when the Python expression is evaluated, the program will report the error and stop. This behavior can be changed with option -i (ignore): using this option, no errors will be reported when evaluating the Python expression and the program will continue to run.

Option --encoding can be used to specify the encoding of the text file to be read. For example, to read a 16-bit Unicode text file, use option "--encoding utf-16".
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

DEFAULT_SEPARATOR = ';'
LIBRARY_EXTENSION = '.library'

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

class cVariables():
    def __init__(self, variablesstring='', separator=DEFAULT_SEPARATOR):
        self.dVariables = {}
        if variablesstring == '':
            return
        for variable in variablesstring.split(separator):
            name, value = VariableNameValue(variable)
            self.dVariables[name] = value

    def SetVariable(self, name, value):
        self.dVariables[name] = value

    def Instantiate(self, astring):
        for key, value in self.dVariables.items():
            astring = astring.replace('%' + key + '%', value)
        return astring

class cOutput():
    def __init__(self, filenameOption=None):
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.f = None
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles:
                    self.f = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.f = open(self.filenameOption, 'w')

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.log' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                if len(self.filename) == 0:
                    self.separateFiles = False
                    return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def Line(self, line, eol='\n'):
        if not self.f or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding))
#            sys.stdout.flush()
        if self.f:
            self.f.write(line + '\n')

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename):
        self.separateFilename = filename
        if self.progress:
            print(self.separateFilename)
        if self.separateFiles:
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.f = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cOutputOptions():
    def __init__(self, option):
        self.option = option
        self.filename = ''
        self.bothoutputs = False
        self.generate = False
        if not option.startswith('#'):
            self.filename = option
            return
        if option.startswith('#l#'):
            self.filename = option[3:]
            return
        result = option[1:].split('#', 1)
        if len(result) == 1:
            raise Exception('cOutputOptions: error')
        for toggle in result[0]:
            if 'c' == toggle:
                self.bothoutputs = True
            elif 'g' == toggle:
                self.generate = True
            else:
                raise Exception('cOutputOptions: toggle error')
        self.filename = result[1]
        return

class cOutputResult():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options

    def Line(self, line, eol='\n'):
        self.oOutput.Line(line, eol)

    def LineTimestamped(self, line):
        self.oOutput.LineTimestamped(line)

    def Filename(self, filename):
        self.oOutput.Filename(filename)

    def Close(self):
        self.oOutput.Close()

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

def ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, split, fullread):
    if fIn == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False

    if isinstance(fIn, list) and isinstance(fIn[0], int):
        for index in range(fIn[0], fIn[1], fIn[2]):
            yield str(index)
    elif isinstance(fIn, list):
        for item in fIn:
            yield item
    elif fullread:
        yield fIn.read()
    else:
        for rawline in fIn:
            rawline = rawline.rstrip('\n\r')
            if split == '':
                lines = [rawline]
            else:
                lines = rawline.split(split)
            for line in lines:
                if not begin:
                    begin, line = oBeginGrep.Grep(line)
                if not begin:
                    continue
                if not end and oEndGrep != None and oEndGrep.dogrep:
                    end, line = oEndGrep.Grep(line)
                    if end:
                        returnendline = True
                if end and not returnendline:
                    continue
                selected = True
                if oGrep != None and oGrep.dogrep:
                    selected, line = oGrep.Grep(line)
                if not selected:
                    continue
                if end and returnendline:
                    returnendline = False
                yield line

def Duckify(line):
    result = ['ENTER']
    if line !='':
        result[0:0] = ['STRING ' + line]
    return result

def OutputResult(result, oOutput, options):
    if not isinstance(result, list):
        result = [result]
    for item in result:
        if options.join == None:
            oOutput.Line(item)
        else:
            oOutput.Line(item, options.join)

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

class cEnumeration(object):
    def __init__(self, iterable, function=lambda x: x, Cache=None):
        self.iterable = iterable
        self.function = function
        self.namedTuple = collections.namedtuple('member', 'item item_t index counter remaining total first last left left_t right right_t cached cache_hits cache_misses Cache Redo redo_counter remaining_seconds eta')
        self.flagRedo = False
        self.oCache = Cache
        self.cache_hits = 0
        self.cache_misses = 0
        self.timeStart = time.time()

    def __iter__(self):
        self.index = -1
        self.total = len(self.iterable)
        if self.oCache != None and self.oCache.cachedFirst:
            self.iterable = sorted(self.iterable, key=lambda x: not self.oCache.Exists(x))
        return self

    def Redo(self, counter):
        if self.nt.redo_counter < counter:
            self.nt = self.namedTuple(self.nt.item, self.nt.item_t, self.nt.index, self.nt.counter, self.nt.remaining, self.nt.total, self.nt.first, self.nt.last, self.nt.left, self.nt.left_t, self.nt.right, self.nt.right_t, self.nt.cached, self.nt.cache_hits, self.nt.cache_misses, self.nt.Cache, self.nt.Redo, self.nt.redo_counter + 1, self.nt.remaining_seconds, self.nt.eta)
            self.flagRedo = True
            return True
        else:
            self.flagRedo = False
            return False

    def Cache(self, result):
        if self.oCache == None:
            return False
        else:
            return self.oCache.Cache(self.nt.item, result, self.nt.last)

    def __next__(self):
        timeNow = time.time()
        if self.flagRedo:
            self.flagRedo = False
            return self.nt
        if self.index < self.total - 1:
            self.index += 1
            first = self.index == 0
            last = self.index == self.total - 1
            if first:
                left = None
                left_t = None
                self.item = self.iterable[self.index]
                self.item_t = self.function(self.item)
            else:
                left = self.item
                left_t = self.item_t
                self.item = self.right
                self.item_t = self.right_t
            if last:
                self.right = None
                self.right_t = None
            else:
                self.right = self.iterable[self.index + 1]
                self.right_t = self.function(self.right)
            if self.oCache == None:
                cachedResult = None
            else:
                cachedResult = self.oCache.Retrieve(self.item)
            if cachedResult == None:
                self.cache_misses += 1
            else:
                self.cache_hits += 1
            try:
                remainingSeconds = (self.total - self.index - 1) / (self.cache_misses / (timeNow - self.timeStart))
            except ZeroDivisionError:
                remainingSeconds = 0
            eta = FormatTime(time.time() + remainingSeconds)
            self.nt = self.namedTuple(self.item, self.item_t, self.index, self.index + 1, self.total - self.index - 1, self.total, first, last, left, left_t, self.right, self.right_t, cachedResult, self.cache_hits, self.cache_misses, self.Cache, self.Redo, 0, remainingSeconds, eta)
            return self.nt
        raise StopIteration

class cStartsWithGetRemainder():

    def __init__(self, strIn, strStart):
        self.strIn = strIn
        self.strStart = strStart
        self.match = False
        self.remainder = None
        if self.strIn.startswith(self.strStart):
            self.match = True
            self.remainder = self.strIn[len(self.strStart):]

def PythonPerLineSingle(expression, filename, oBeginGrep, oGrep, oEndGrep, oOutput, options):
    if filename == '':
        if options.encoding != '':
            sys.stdin.reconfigure(encoding=options.encoding)
        fIn = sys.stdin
    elif isinstance(filename, list):
        fIn = filename
    elif os.path.splitext(filename)[1].lower() == '.gz':
        fIn = gzip.GzipFile(filename, 'rb')
    elif options.encoding == '':
        fIn = open(filename, 'r')
    else:
        fIn = open(filename, 'r', encoding=options.encoding)
    lineNumber = 0
    if options.regex != '':
        oRE = re.compile(options.regex, re.I)
    else:
        oRE = None

    if options.group:
        lines = []
        for line in ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, options.split, False):
            lines.append(line)
        try:
            result = eval(expression)
        except:
            result = []
            if not options.ignore:
                raise
        OutputResult(result, oOutput, options)
    elif options.object:
        expressionToEvaluate = expression + '(oLine)'
        for oLine in cEnumeration(list(ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, options.split, False))):
            if oRE != None:
                oMatch = oRE.search(oLine.item)
                if oMatch == None:
                    continue
            try:
                result = eval(expressionToEvaluate)
            except:
                result = []
                if not options.ignore:
                    raise
            OutputResult(result, oOutput, options)
    else:
        for line in ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, options.split, False):
            lineNumber += 1
            expressionToEvaluate = expression.replace('{}', repr(line))
            if oRE != None:
                oMatch = oRE.search(line)
                if oMatch == None:
                    continue
            try:
                result = eval(expressionToEvaluate)
            except:
                result = []
                if not options.ignore:
                    raise
            OutputResult(result, oOutput, options)

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

def LoadScriptIfExists(filename):
    if os.path.exists(filename):
        exec(open(filename, 'r').read(), globals(), globals())

def PythonPerLine(expression, filenames, options):
    if options.name:
        expression += '(line)'

    if options.execute != '':
        exec(options.execute, globals())

    if options.script != '':
        LoadScriptIfExists(options.script)
    LoadScriptIfExists(os.path.splitext(sys.argv[0])[0] + LIBRARY_EXTENSION)
    LoadScriptIfExists(os.path.splitext(os.path.basename(sys.argv[0]))[0] + LIBRARY_EXTENSION)

    oGrep = cGrep(options.grep, options.grepoptions)
    oBeginGrep = cGrep(options.begingrep, options.begingrepoptions)
    oEndGrep = cGrep(options.endgrep, options.endgrepoptions)
    oOutput = cOutputResult(options)
    for filename in filenames:
        oOutput.Filename(filename)
        PythonPerLineSingle(expression, filename, oBeginGrep, oGrep, oEndGrep, oOutput, options)
    oOutput.Close()

def CheckArgumentsAndOptions(oParser, args, options):
    if options.man:
        oParser.print_help()
        PrintManual()
        return True

    if len(args) == 0:
        oParser.print_help()
        return True

    if options.range != '' and len(args) != 1:
        oParser.print_help()
        return True

#    optionStrings = [option.get_opt_string() for option in oParser.option_list]
#    if '--output' in optionStrings and '--outputgeneratedfilename' in optionStrings and options.output != '' and options.outputgeneratedfilename:
#        oParser.error('options --output and --outputgeneratedfilename are mutually exclusive')

    return False

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
    oParser.add_option('-n', '--name', action='store_true', default=False, help='The expression is the name of a Python function to apply on each selected line')
    oParser.add_option('-O', '--object', action='store_true', default=False, help='The expression is a Python function that receives a line object per selected line')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-s', '--script', type=str, default='', help='Script with definitions to include')
    oParser.add_option('-e', '--execute', default='', help='Commands to execute')
    oParser.add_option('-r', '--range', type=str, default='', help='Parameters to generate input with range')
    oParser.add_option('-l', '--list', type=str, default='', help='List with lines to process (comma separated)')
    oParser.add_option('-i', '--ignore', action='store_true', default=False, help='Ignore errors when evaluating the expression')
    oParser.add_option('-R', '--regex', type=str, default='', help='Regular expression to apply to each line')
    oParser.add_option('-j', '--join', type=str, default=None, help='Join lines together')
    oParser.add_option('-g', '--group', action='store_true', default=False, help='Group all lines into variable lines')
    oParser.add_option('--grep', type=str, default='', help='Grep expression')
    oParser.add_option('--grepoptions', type=str, default='', help='Grep options (ivF)')
    oParser.add_option('--begingrep', type=str, default='', help='Grep expression for begin line')
    oParser.add_option('--begingrepoptions', type=str, default='', help='begingrep options (ivF)')
    oParser.add_option('--endgrep', type=str, default='', help='Grep expression for end line')
    oParser.add_option('--endgrepoptions', type=str, default='', help='endgrep options (ivF)')
    oParser.add_option('--split', type=str, default='', help='Split per string')
    oParser.add_option('--encoding', type=str, default='', help='Encoding for file open')
    (options, args) = oParser.parse_args()

    if CheckArgumentsAndOptions(oParser, args, options):
        return

    if options.range != '':
        PythonPerLine(args[0], [ParseRange(options.range)], options)
    elif options.list != '':
        PythonPerLine(args[0], [options.list.split(',')], options)
    elif len(args) == 1:
        PythonPerLine(args[0], [''], options)
    else:
        PythonPerLine(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
