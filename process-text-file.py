#!/usr/bin/env python

from __future__ import print_function

__description__ = "Template for text file processing"
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2021/02/27'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/02/02: start
  2017/12/16: added handling of unicode errors Python 3
  2018/04/17: added # support to option -o
  2018/06/17: fixed Linux file processing
  2018/06/29: added options --grep and --grepoptions
  2018/07/05: introduced cExpandFilenameArguments; refactoring; added logging
  2018/07/07: refactoring
  2018/07/28: added options --begingrep, --begingrepoptions, --endgrep, and --endgrepoptions
  2018/09/18: added eta to progress
  2018/10/08: added %ru% to cOutput; added search and replace
  2018/10/20: added eol to cOutput.Line
  2020/02/22: 0.0.2 added option --context
  2020/11/11: 0.0.3 added option --encoding
  2021/02/14: 0.0.4 File2Strings fix & Strings2File
  2021/02/27: Changed encoding

Todo:
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import os
import gzip
import re
import fnmatch
import collections
from contextlib import contextmanager

def PrintManual():
    manual = '''
Manual:

Errors occuring when opening a file are reported (and logged if logging is turned on), and the program moves on to the next file.
Errors occuring when reading & processing a file are reported (and logged if logging is turned on), and the program stops unless option ignoreprocessingerrors is used.

Option --encoding can be used to specify the encoding of the text file to be read. For example, to read a 16-bit Unicode text file, use option "--encoding utf-16".

Option --grep can be used to select (grep) lines that have to be processed.
If this option is not used, all lines will be processed.
To select particular lines to be processed, used option --grep and provide a regular expression. All lines matching this regular expression will be processed.
You can also use a capture group in your regular expression. The line to be processed will become the content of the first capture group (and not the complete line).
The regular expression matching operation is case sensitive. Use option --grepoptions i to make the matching operation case insensitive.
Use option --grepoptions v to invert the selection.
Use option --grepoptions F to match a fixed string in stead of a regular expression.

Option --context can be used to select which lines have to be processed when a line is "grepped". If no context is provided, only "grepped" lines are processed.
But if you want to process other lines, use option --context. The value for this option is a list of line numbers/ranges separated by a comma. The line numbers are relative to the "grepped" line.
A number is negative, zero or positive integer. A range is 2 numbers separated by a dash (-).
For example, line number -1 is the line right before the "grepped" line (0 is the "grepped" line itself).
Example to select the line before a line containing "trigger" and the second line after the trigger line: --grep trigger --context -1,2

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

Options --search and --replace can be used to replace every occurence of option value --search in each line by option value --replace (can be an empty string).
--searchoptions are available too.

The lines are written to standard output, except when option -o is used. When option -o is used, the lines are written to the filename specified by option -o.
Filenames used with option -o starting with # have special meaning.
#c#example.txt will write output both to the console (stdout) and file example.txt.
#g# will write output to a file with a filename generated by the tool like this: toolname-date-time.txt.
#g#KEYWORD will write output to a file with a filename generated by the tool like this: toolname-KEYWORD-date-time.txt.
Use #p#filename to display execution progress.
To process several files while creating seperate output files for each input file, use -o #s#%f%.result *.
This will create output files with the name of the inputfile and extension .result.
There are several variables available when creating separate output files:
 %f% is the full filename (with directory if present)
 %b% is the base name: the filename without directory
 %d% is the directory
 %r% is the root: the filename without extension
 %ru% is the root made unique by appending a counter (if necessary)
 %e% is the extension
Most options can be combined, like #ps# for example.
#l# is used for literal filenames: if the output filename has to start with # (#example.txt for example), use filename #l##example.txt for example.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

DEFAULT_SEPARATOR = ','
QUOTE = '"'

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return tuple(map(lambda line:line.rstrip('\n'), f.readlines()))
    except:
        return None
    finally:
        f.close()

def Strings2File(filename, lines):
    try:
        f = open(filename, 'w')
    except:
        return None
    try:
        for line in lines:
            f.write(line + '\n')
        return True
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
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')

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
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

class cExpandFilenameArguments():
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False, expressionprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ''
        self.filenameexpressions = []
        self.expressionprefix = expressionprefix
        self.literalfilenames = literalfilenames

        expression = ''
        if len(filenames) == 0:
            self.filenameexpressions = [['', '']]
        elif literalfilenames:
            self.filenameexpressions = [[filename, ''] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix != None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix):]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressions.append([filename, expression])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressions.append([dirwildcard, expression])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = '*'
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == '':
                                dirname = '.'
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                self.filenameexpressions.append([os.path.join(path, filename), expression])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix != None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix):]
                else:
                    self.filenameexpressions.append([filename, expression])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressions) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressions == [] and expression != '':
            self.filenameexpressions = [['', expression]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ('?' in filename or '*' in filename or ('[' in filename and ']' in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression in self.filenameexpressions:
            hashfile = False
            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except:
                pass
            if filename == '' or hashfile:
                valid.append([filename, expression])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression])
        self.filenameexpressions = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += 'The following files do not exist and will be skipped: ' + ' '.join(doesnotexist) + '\n'
        if len(isnotafile) > 0:
            self.warning = True
            self.message += 'The following files are not regular files and will be skipped: ' + ' '.join(isnotafile) + '\n'

    def Filenames(self):
        if self.expressionprefix == None:
            return [filename for filename, expression in self.filenameexpressions]
        else:
            return self.filenameexpressions

def ToString(value):
    if isinstance(value, str):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value or value == '':
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

class cLogfile():
    def __init__(self, keyword, comment):
        self.starttime = time.time()
        self.errors = 0
        if keyword == '':
            self.oOutput = None
        else:
            self.oOutput = cOutput('%s-%s-%s.log' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], keyword, self.FormatTime()))
        self.Line('Start')
        self.Line('UTC', '%04d%02d%02d-%02d%02d%02d' % time.gmtime(time.time())[0:6])
        self.Line('Comment', comment)
        self.Line('Args', repr(sys.argv))
        self.Line('Version', __version__)
        self.Line('Python', repr(sys.version_info))
        self.Line('Platform', sys.platform)
        self.Line('CWD', repr(os.getcwd()))

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def Line(self, *line):
        if self.oOutput != None:
            self.oOutput.Line(MakeCSVLine((self.FormatTime(), ) + line, DEFAULT_SEPARATOR, QUOTE))

    def LineError(self, *line):
        self.Line('Error', *line)
        self.errors += 1

    def Close(self):
        if self.oOutput != None:
            self.Line('Finish', '%d error(s)' % self.errors, '%d second(s)' % (time.time() - self.starttime))
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

def SearchAndReplace(line, search, replace, searchoptions):
    return line.replace(search, replace)

def ProcessFileWithoutContext(fIn, oBeginGrep, oGrep, oEndGrep, options, fullread):
    if fIn[0] == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False
    if fullread:
        yield fIn[0].read()
    else:
        for line in fIn[0]:
            if fIn[1] == 2:
                line = line.decode(*ParseOptionEncoding(options.encoding))
            line = line.rstrip('\n\r')
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
            if options.search != '':
                line = SearchAndReplace(line, options.search, options.replace, options.searchoptions)
            yield line

def ProcessFileWithContext(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread):
    if fIn[0] == None:
        return

    begin = oBeginGrep == None or not oBeginGrep.dogrep
    end = False
    returnendline = False
    lineCounter = 0
    if len(context) >= 2:
        queueSize = context[1] - context[0] + 1
    elif context[0] < 0:
        queueSize = 0 - context[0] + 1
    else:
        queueSize = context[0] - 0 + 1
    queue = collections.deque([[-1, ''] for i in range(0, queueSize)])
    lineNumbers = []

    if fullread:
        yield fIn[0].read()
    else:
        for line in fIn[0]:
            lineCounter += 1
            if fIn[1] == 2:
                line = line.decode(*ParseOptionEncoding(options.encoding))
            line = line.rstrip('\n\r')
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
            queue.popleft()
            queue.append([lineCounter, line])
            selected, line = oGrep.Grep(line)
            if selected:
                lineNumbers = sorted(set(lineNumbers + [lineCounter + offset for offset in context]))
            if lineNumbers == []:
                continue
            else:
                for lineKey, lineValue in queue:
                    if lineNumbers[0] == lineKey:
                        line = lineValue
                        lineNumbers = lineNumbers[1:]
                        break
            if end and returnendline:
                returnendline = False
            if options.search != '':
                line = SearchAndReplace(line, options.search, options.replace, options.searchoptions)
            yield line
        for line in lineNumbers:
            for lineKey, lineValue in queue:
                if line == lineKey:
                    yield lineValue
                    break

def ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread):
    if oGrep != None and context != []:
        return ProcessFileWithContext(fIn, oBeginGrep, oGrep, oEndGrep, context, options, fullread)
    else:
        return ProcessFileWithoutContext(fIn, oBeginGrep, oGrep, oEndGrep, options, fullread)

def AnalyzeFileError(filename):
    PrintError('Error opening file %s' % filename)
    PrintError(sys.exc_info()[1])
    try:
        if not os.path.exists(filename):
            PrintError('The file does not exist')
        elif os.path.isdir(filename):
            PrintError('The file is a directory')
        elif not os.path.isfile(filename):
            PrintError('The file is not a regular file')
    except:
        pass

def ParseOptionEncoding(encoding):
    if encoding == '':
        encodingvalue = 'utf8'
        errorsvalue = 'surrogateescape'
    else:
        encodingvalue = encoding
        errorsvalue = None
    return encodingvalue, errorsvalue

@contextmanager
def TextFile(filename, oLogfile, options):
    fType = 0
    if filename == '':
        fIn = sys.stdin
        fType = 1
    elif os.path.splitext(filename)[1].lower() == '.gz':
        try:
            fIn = gzip.GzipFile(filename, 'rb')
            fType = 2
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None
    else:
        try:
            fIn = open(filename, 'r', encoding=ParseOptionEncoding(options.encoding)[0], errors=ParseOptionEncoding(options.encoding)[1])
        except:
            AnalyzeFileError(filename)
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            fIn = None

    if fIn != None:
        oLogfile.Line('Success', 'Opening file %s' % filename)

    yield (fIn, fType)

    if fIn != None:
        if sys.exc_info()[1] != None:
            oLogfile.LineError('Reading file %s %s' % (filename, repr(sys.exc_info()[1])))
        if fType != 1:
            fIn.close()

def ProcessTextFile(filename, oBeginGrep, oGrep, oEndGrep, context, oOutput, oLogfile, options):
    with TextFile(filename, oLogfile, options) as fIn:
        try:
            for line in ProcessFile(fIn, oBeginGrep, oGrep, oEndGrep, context, options, False):
                # ----- Put your line processing code here -----
                oOutput.Line(line)
                # ----------------------------------------------
        except:
            oLogfile.LineError('Processing file %s %s' % (filename, repr(sys.exc_info()[1])))
            if not options.ignoreprocessingerrors:
                raise
            if sys.version_info[0] < 3:
                sys.exc_clear()

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

def ParseNumber(number):
    negative = 1
    if number[0] == '-':
        negative = -1
        number = number[1:]
    elif number[0] == '+':
        number = number[1:]
    digits = ''
    while len(number) > 0 and number[0] >= '0' and number[0] <= '9':
        digits += number[0]
        number = number[1:]
    return negative * int(digits), number

def ParseTerm(term):
    start, remainder = ParseNumber(term)
    if len(remainder) == 0:
        return [start]
    if remainder[0] == '-':
        remainder = remainder[1:]
        stop, remainder = ParseNumber(remainder)
        if len(remainder) > 0:
            raise Exception('Error parsing term: ' + term)
        return list(range(start, stop + 1))
    else:
        raise Exception('Error parsing term: ' + term)

def ParseContext(context):
    lines = []
    for term in context.replace(' ', '').split(','):
        lines += ParseTerm(term)
    return sorted(set(lines))

def ProcessTextFiles(filenames, oLogfile, options):
    oGrep = cGrep(options.grep, options.grepoptions)
    oBeginGrep = cGrep(options.begingrep, options.begingrepoptions)
    oEndGrep = cGrep(options.endgrep, options.endgrepoptions)
    oOutput = InstantiateCOutput(options)
    if oGrep == None or not oGrep.dogrep:
        context = []
    elif options.context == '':
        context = []
    else:
        context = ParseContext(options.context)

    for index, filename in enumerate(filenames):
        oOutput.Filename(filename, index, len(filenames))
        ProcessTextFile(filename, oBeginGrep, oGrep, oEndGrep, context, oOutput, oLogfile, options)

    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('--grep', type=str, default='', help='Grep expression')
    oParser.add_option('--grepoptions', type=str, default='', help='grep options (ivF)')
    oParser.add_option('--context', type=str, default='', help='Grep context (lines to select)')
    oParser.add_option('--begingrep', type=str, default='', help='Grep expression for begin line')
    oParser.add_option('--begingrepoptions', type=str, default='', help='begingrep options (ivF)')
    oParser.add_option('--endgrep', type=str, default='', help='Grep expression for end line')
    oParser.add_option('--endgrepoptions', type=str, default='', help='endgrep options (ivF)')
    oParser.add_option('--search', type=str, default='', help='Search term (search and replace)')
    oParser.add_option('--replace', type=str, default='', help='Replace term (search and replace)')
    oParser.add_option('--searchoptions', type=str, default='', help='Search options (search and replace)')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--recursedir', action='store_true', default=False, help='Recurse directories (wildcards and here files (@...) allowed)')
    oParser.add_option('--checkfilenames', action='store_true', default=False, help='Perform check if files exist prior to file processing')
    oParser.add_option('--logfile', type=str, default='', help='Create logfile with given keyword')
    oParser.add_option('--logcomment', type=str, default='', help='A string with comments to be included in the log file')
    oParser.add_option('--ignoreprocessingerrors', action='store_true', default=False, help='Ignore errors during file processing')
    oParser.add_option('--encoding', type=str, default='', help='Encoding for file open')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    oLogfile = cLogfile(options.logfile, options.logcomment)

    oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir, options.checkfilenames)
    oLogfile.Line('FilesCount', str(len(oExpandFilenameArguments.Filenames())))
    oLogfile.Line('Files', repr(oExpandFilenameArguments.Filenames()))
    if oExpandFilenameArguments.warning:
        PrintError('\nWarning:')
        PrintError(oExpandFilenameArguments.message)
        oLogfile.Line('Warning', repr(oExpandFilenameArguments.message))

    ProcessTextFiles(oExpandFilenameArguments.Filenames(), oLogfile, options)

    if oLogfile.errors > 0:
        PrintError('Number of errors: %d' % oLogfile.errors)
    oLogfile.Close()

if __name__ == '__main__':
    Main()
