#!/usr/bin/env python

__description__ = 'This is essentially a wrapper for xml.etree.ElementTree'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/12/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/11/03: start
  2017/12/16: refactoring

Todo:
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import xml.etree.ElementTree

def PrintManual():
    manual = r'''
Manual:

xmldump.py can be used to extract information from XML files, it is essentially a wrapper for xml.etree.ElementTree.

This Python script was developed with Python 2.7 and tested with Python 2.7 and 3.5.

It reads one or more files or stdin to parse XML files. If no file arguments are provided to this tool, it will read data from standard input (stdin). This way, this tool can be used in a piped chain of commands.

The first argument to the tool is a command, which can be:
 text
 wordtext
 
Command text will extract all text from the elements in the XML file.
Example:
zipdump.py -s 4 -d test.docx | xmldump.py text

This is a test document.Second line.Third linehttps://DidierStevens.comLast line

Command wordtext will extract all text from <w:p> elements in the XML file and print each on a separate line.
Example:
zipdump.py -s 4 -d test.docx | xmldump.py wordtext

This is a test document.
Second line.
Third line
https://DidierStevens.com
Last line

By default, output is printed to the consolde (stdout). It can be directed to a file using option -o.
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
            try:
                print(line)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding))
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

def XMLGetText(element):
    if sys.version_info[0] > 2:
        encoding = 'unicode'
    else:
        encoding = 'utf8'
    return xml.etree.ElementTree.tostring(element, encoding=encoding, method='text')

def ExtractText(root, oOutput, options):
    oOutput.Line(XMLGetText(root))

def ExtractWordText(root, oOutput, options):
    for element in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
        oOutput.Line(XMLGetText(element))

dCommands = {'text': ExtractText, 'wordtext': ExtractWordText}

def ProcessTextFileSingle(command, filenames, oOutput, options):
    for filename in filenames:
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        root = xml.etree.ElementTree.parse(fIn).getroot()
        if fIn != sys.stdin:
            fIn.close()
        dCommands[command](root, oOutput, options)
1
def ProcessTextFile(command, filenames, options):
    oOutput = cOutputResult(options)
    ProcessTextFileSingle(command, filenames, oOutput, options)
    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] command [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        return

    command = args[0]

    if not command in dCommands:
        print('Invalid command: %s' % command)
        print('List of valid commands: %s' % ' '.join(dCommands.keys()))
        return

    if len(args) == 1:
        ProcessTextFile(command, [''], options)
    else:
        ProcessTextFile(command, ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
