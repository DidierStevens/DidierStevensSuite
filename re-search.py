#!/usr/bin/env python

__description__ = "Program to use Python's re.findall on files"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/07/07'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/12/06: start
  2013/12/15: added re-search.txt support, options -b -s
  2014/03/25: added ipv4
  2014/04/03: added extra regex comments
  2014/04/09: refactoring: module reextra
  2014/07/18: added manual, stdin
  2014/09/16: updated manual
  2014/09/17: added exception handling for import reextra
  2014/10/10: added options csv, grep and removeanchor
  2014/11/04: updated man
  2014/11/13: added error handling to CompileRegex
  2015/07/07: added option fullread

Todo:
  add hostname to header
"""

import optparse
import glob
import collections
import re
import sys
import os
import pickle
import math
import textwrap
import csv

try:
    import reextra
except:
    print("This program requires module reextra (it is a part of the re-search package).\nMake sure it is installed in Python's module repository or the same folder where re-search.py is installed.")
    exit(-1)

dLibrary = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}',
            'url': r'[a-zA-Z]+://[-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[a-zA-Z0-9+&@#/%=~_|!:,.;]*)?',
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b',
           }

def PrintManual():
    manual = '''
Manual:

re-search is a program to match regular expressions. It is like grep -o, it will match regular expressions in text files, not the complete line.

It has 2 major features: a small, extendable library of regular expressions selectable by name; and extra functionality like gibberish detection and whitelists/blacklists.

We will use this list of URLs in our examples:
http://didierstevens.com
http://zcczjhbczhbzhj.com
http://www.google.com
http://ryzaocnsyvozkd.com
http://www.microsoft.com
http://ahsnvyetdhfkg.com

Example to extract alphabetical .com domains from file list.txt with a regular expression:
re-search.py [a-z]+\.com list.txt

Output:
didierstevens.com
zcczjhbczhbzhj.com
google.com
ryzaocnsyvozkd.com
microsoft.com
ahsnvyetdhfkg.com

Example to extract URLs from file list.txt with the build-in regular expression for URLs:
re-search.py -n url list.txt

Output:
http://didierstevens.com
http://zcczjhbczhbzhj.com
http://www.google.com
http://ryzaocnsyvozkd.com
http://www.microsoft.com
http://ahsnvyetdhfkg.com

You can also use a capture group in your regular expression. The selected text will be extracted from the first capture group:
re-search.py ([a-z]+)\.com list.txt

Output:
didierstevens
zcczjhbczhbzhj
google
ryzaocnsyvozkd
microsoft
ahsnvyetdhfkg

By default the regular expression matching is not case sensitive. You can make it case sensitive with option -c. To surround the regular expression with boundaries (\b), use option -b. Output can be mode lowercase with option -l and unique with option -u. Output can be saved to a file with option -o filename. And if you also want to output the regular expression used for matching, use option -d.
To get grep-like output, use option -g. Option -r removes the anchor (^and $) or the regular expression.
By default, re-search reads the file(s) line-by-line. Binary files can also be processed, but are best read completely and not line-by-line. Use option -f (fullread) to perform a fule read of the file (and not line-by-line).

If you have a list of regular expressions to match, put them in a csv file, and use option -v, -S, -I, -H, -R and -C.
Example:
re-search.py -vHrg -o result -S , -I " " -R PCRE -C pcre.csv logs

Gibberish detection and whitelists/blacklists filtering is done by prefixing the regular expression with a comment. Regular expressions can contain comments, like programming languages. This is a comment for regular expressions: (?#comment).
If you use re-search with regular expression comments, nothing special happens:
re-search.py "(?#comment)[a-z]+\.com" list.txt

However, if your regular expression comment prefixes the regular expression, and the comment starts with keyword extra=, then you can use gibberish detection and whitelist/blacklist filtering.
To use gibberisch detection, you use directive S (S stands for sensical). If you want to filter all strings that match the regular expression and are gibberish, you use the following regular expression comment: (?#extra=S:g). :g means that you want to filter for gibberish.

Example to extract alphabetical .com domains from file list.txt with a regular expression that are gibberish:
re-search.py "(?#extra=S:g)[a-z]+\.com" list.txt

Output:
zcczjhbczhbzhj.com
ryzaocnsyvozkd.com
ahsnvyetdhfkg.com

If you want to filter all strings that match the regular expression and are not gibberish, you use the following regular expression comment: (?#extra=S:s). :s means that you want to filter for sensical strings.

Example to extract alphabetical .com domains from file list.txt with a regular expression that are not gibberish:
re-search.py "(?#extra=S:s)[a-z]+\.com" list.txt

Output:
didierstevens.com
google.com
microsoft.com

Blacklists are defined via directive E (Exclude). If you want to filter all strings that match the regular expression and are not in the blacklist, you use the following regular expression comment: (?#extra=E:blacklist). blacklist is a textfile you provide containing all the strings to be blacklisted.

Example to extract alphabetical .com domains from file list.txt with a regular expression that are not in file blacklist (blacklist contains google.com):
re-search.py "(?#extra=E:blacklist)[a-z]+\.com" list.txt

Output:
didierstevens.com
zcczjhbczhbzhj.com
ryzaocnsyvozkd.com
microsoft.com
ahsnvyetdhfkg.com

Whitelists are defined via directive I (Include). If you want to filter all strings that match the regular expression and are in the whitelist, you use the following regular expression comment: (?#extra=I:whitelist). Whitelist is a textfile you provide containing all the strings to be whitelisted.

Example to extract alphabetical .com domains from file list.txt with a regular expression that are in file whitelist (whitelist contains didierstevens.com):
re-search.py "(?#extra=I:whitelistlist)[a-z]+\.com" list.txt

Output:
didierstevens.com

You can use more than one directive in a regular expression. Directives are separated by the ; character.

Example to extract alphabetical .com domains from file list.txt with a regular expression that are not gibberish and that are not blacklist:
re-search.py "(?#extra=S:s;E:blacklist)[a-z]+\.com" list.txt

Output:
didierstevens.com
microsoft.com


Classifying a string as gibberish or not, is done with a set of classes that I developed based on work done by rrenaud at https://github.com/rrenaud/Gibberish-Detector. The training text is a public domain book in the Sherlock Holmes series. This means that English text is used for gibberish classification. You can provide your own trained pickle file with option -s.

You can extend the library of regular expressions used by re-search without changing the program source code. Create a text file named re-search.txt located in the same directory as re-search.py. For each regular expression you want to add to the library, enter a line with format name=regex. Here is an example for MAC addresses:

mac=[0-9A-F]{2}([-:]?)(?:[0-9A-F]{2}\1){4}[0-9A-F]{2}

re-search.py requires module reextra, which is part of the re-search package.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

QUOTE = '"'

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

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

def PrintLibrary():
    global dLibrary

    print('Valid regex library names:')
    for key in sorted(dLibrary.keys()):
        print(' %s: %s' % (key, dLibrary[key]))

def MergeUserLibrary():
    global dLibrary

    lines = File2Strings(os.path.splitext(sys.argv[0])[0] + '.txt')
    if not lines:
        return
    for line in lines:
        if not line.startswith('#'):
            result = line.split('=')
            if len(result) == 2:
                dLibrary[result[0]] = result[1]

def Library(name):
    global dLibrary

    MergeUserLibrary()

    try:
        return dLibrary[name]
    except KeyError:
        print('Invalid regex library name: %s' % name)
        print('')
        PrintLibrary()
        sys.exit(-1)

class cOutputResult():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options
        self.dLines = {}

    def Line(self, line):
        line = IFF(self.options.lower, lambda: line.lower(), line)
        if not line in self.dLines:
            self.oOutput.Line(line)
        if self.options.unique and not line in self.dLines:
            self.dLines[line] = True

    def Close(self):
        self.oOutput.Close()

def CompileRegex(regex, options):
    regex = IFF(options.name, lambda: Library(regex), regex)
    if options.removeanchor:
        regex = IFF(regex.startswith('^'), regex[1:], regex)
        regex = IFF(regex.endswith('$'), regex[:-1], regex)
    regex = IFF(options.boundary, '\\b%s\\b' % regex, regex)
    try:
        oREExtra = reextra.cREExtra(regex, IFF(options.casesensitive, 0, re.IGNORECASE), options.sensical)
    except:
        print('Error regex: %s' % regex)
        raise
    return regex, oREExtra

def ProcessFile(fIn, fullread):
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n')

def RESearchSingle(regex, filenames, oOutput, options):
    regex, oREExtra = CompileRegex(regex, options)
    if options.display:
        oOutput.Line('Regex: %s' % regex)
    for filename in filenames:
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        for line in ProcessFile(fIn, options.fullread):
            results = oREExtra.Findall(line)
            if options.grep:
                if results != []:
                    oOutput.Line(line)
            else:
                for result in results:
                    if isinstance(result, str):
                        oOutput.Line(result)
                    if isinstance(result, tuple):
                        oOutput.Line(result[0])
        if fIn != sys.stdin:
            fIn.close()

def RESearchCSV(csvFilename, filenames, oOutput, options):
    reader = csv.reader(open(csvFilename, 'r'), delimiter=options.separatorcsv, skipinitialspace=False, quoting=IFF(options.unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
    indexRegex = 0
    indexComment = None
    if not options.header:
        if options.regexindex != '':
            indexRegex = int(options.regexindex)
        if options.commentindex != '':
            indexComment = int(options.commentindex)
    firstRow = True
    dRegex = {}
    for row in reader:
        if options.header and firstRow:
            firstRow = False
            if options.regexindex != '':
                indexRegex = row.index(options.regexindex)
            if options.commentindex != '':
                indexComment = row.index(options.commentindex)
            continue
        regex, oREExtra = CompileRegex(row[indexRegex], options)
        if options.display:
            oOutput.Line('Regex: %s' % row[indexRegex])
        dRegex[regex] = (oREExtra, IFF(indexComment == None, None, lambda: row[indexComment]))

    for filename in filenames:
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        for line in ProcessFile(fIn, options.fullread):
            for regex, (oREExtra, comment) in dRegex.items():
                results = oREExtra.Findall(line)
                newRow = [regex]
                if comment != None:
                    newRow.append(comment)
                if options.grep:
                    if results != []:
                        if options.separatorinput == '':
                            newRow.append(line)
                            outputLine = MakeCSVLine(newRow, options.separatorcsv, QUOTE)
                        else:
                            outputLine = MakeCSVLine(newRow, options.separatorinput, QUOTE) + options.separatorinput + line
                        oOutput.Line(outputLine)
                else:
                    for result in results:
                        if isinstance(result, str):
                            if options.separatorinput == '':
                                newRow.append(result)
                                outputLine = MakeCSVLine(newRow, options.separatorcsv, QUOTE)
                            else:
                                outputLine = MakeCSVLine(newRow, options.separatorinput, QUOTE) + options.separatorinput + result
                        if isinstance(result, tuple):
                            if options.separatorinput == '':
                                newRow.append(result[0])
                                outputLine = MakeCSVLine(newRow, options.separatorcsv, QUOTE)
                            else:
                                outputLine = MakeCSVLine(newRow, options.separatorinput, QUOTE) + options.separatorinput + result[0]
                        oOutput.Line(outputLine)
        if fIn != sys.stdin:
            fIn.close()

def RESearch(regex, filenames, options):
    oOutput = cOutputResult(options)
    if options.csv:
        RESearchCSV(regex, filenames, oOutput, options)
    else:
        RESearchSingle(regex, filenames, oOutput, options)
    oOutput.Close()

def Main():
    global dLibrary

    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Valid regex library names:
'''

    MergeUserLibrary()
    for key in sorted(dLibrary.keys()):
        moredesc += ' %s: %s\n' % (key, dLibrary[key])

    moredesc += '''
Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] regex [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-n', '--name', action='store_true', default=False, help='The regex argument is a name of a library regex')
    oParser.add_option('-c', '--casesensitive', action='store_true', default=False, help='Make search case-sensitive')
    oParser.add_option('-l', '--lower', action='store_true', default=False, help='Lowercase output')
    oParser.add_option('-u', '--unique', action='store_true', default=False, help='Unique output')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-b', '--boundary', action='store_true', default=False, help='Add boundaries (\\b) around the regex')
    oParser.add_option('-d', '--display', action='store_true', default=False, help='Display the regex')
    oParser.add_option('-s', '--sensical', default='', help='Sensical pickle file')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-g', '--grep', action='store_true', default=False, help='Outputs the complete line, like grep (without -o)')
    oParser.add_option('-r', '--removeanchor', action='store_true', default=False, help='Remove anchor of regex starting with ^ and/or ending with $')
    oParser.add_option('-v', '--csv', action='store_true', default=False, help='First argument is a CSV file with regular expressions')
    oParser.add_option('-S', '--separatorcsv', default=';', help='Separator character for CSV file (default ;)')
    oParser.add_option('-I', '--separatorinput', default='', help='Separator character for input file (default none)')
    oParser.add_option('-U', '--unquoted', action='store_true', default=False, help='No handling of quotes in CSV file')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='Header')
    oParser.add_option('-R', '--regexindex', default='', help='Index or title of the regex column in the CSV file')
    oParser.add_option('-C', '--commentindex', default='', help='Index or title of the comment column in the CSV file')
    oParser.add_option('-f', '--fullread', action='store_true', default=False, help='Do a full read of the input, not line per line')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
    elif len(args) == 1:
        RESearch(args[0], [''], options)
    else:
        RESearch(args[0], ExpandFilenameArguments(args[1:]), options)

if __name__ == '__main__':
    Main()
