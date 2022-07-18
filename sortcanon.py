#!/usr/bin/env python

__description__ = 'Sort with canonicalization function'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2022/07/17'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/07/07: start
  2015/07/08: added output option
  2022/06/19: update for Python 3
  2022/07/17: 0.0.2 added email

Todo:
"""

import optparse
import glob
import sys
import collections
import textwrap

dLibrary = {
            'domain': "lambda x: '.'.join(x.split('.')[::-1])",
            'length': "lambda x: len(x)",
            'ipv4':   "lambda x: [int(n) for n in x.split('.')]",
            'email':  "lambda x: '.'.join(x.split('@', 1)[1].split('.')[::-1]) + '@' + x.split('@', 1)[0]"
           }

def PrintManual():
    manual = r'''
Manual:

sortcanon is a tool to sort the content of text files according to some canonicalization function.
The tool takes input from stdin or one or more text files provided as argument.
All lines from the different input files are put together and sorted.

If no option is used to select a particular type of sorting, then normal alphabetical sorting is applied.

Use option -o to write the output to the given file, in stead of stdout.

Use option -r to reverse the sort order.

Use option -u to produce a list of unique lines: remove all doubles before sorting.

Option -c can be used to select a particular type of sorting.
For the moment, 2 options are provided:

domain: interpret the content of the text files as domain names, and sort them first by TLD, then domain, then subdomain, and so on ...

length: sort the lines by line length. The longest lines will be printed out last.

ipv4: sort IPv4 addresses.

You can also provide your own Python lambda function to canonicalize each line for sorting.
Remark that this involves the use of the Python eval function: do only use this with trusted input.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))


def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return list(map(lambda line:line.rstrip('\n'), f.readlines()))
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

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

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

def SortCanon(args, options):
    global dLibrary

    lines = []
    for file in args:
        if file == '':
            fIn = sys.stdin
        else:
            fIn = open(file, 'r')
        for line in [line.strip('\n') for line in fIn.readlines()]:
            lines.append(line)
        if file != '':
            fIn.close()

    if options.canonicalize == '':
        Canonicalize = lambda x: x
    elif options.canonicalize in dLibrary:
        Canonicalize = eval(dLibrary[options.canonicalize])
    else:
        Canonicalize = eval(options.canonicalize)

    if options.unique:
        lines = list(set(lines))

    oOutput = cOutput(options.output)
    for line in sorted(lines, key=Canonicalize, reverse=options.reverse):
        oOutput.Line(line)
    oOutput.Close()

def Main():
    global dLibrary

    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Valid Canonicalization function names:
'''

    for key in sorted(dLibrary.keys()):
        moredesc += ' %s: %s\n' % (key, dLibrary[key])

    moredesc += '''
Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [files]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-c', '--canonicalize', default='', help='Canonicalization function')
    oParser.add_option('-r', '--reverse', action='store_true', default=False, help='Reverse sort')
    oParser.add_option('-u', '--unique', action='store_true', default=False, help='Make unique list')
    oParser.add_option('-o', '--output', default='', help='Output file')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        SortCanon([''], options)
    else:
        SortCanon(ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
