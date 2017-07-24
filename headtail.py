#!/usr/bin/env python

__description__ = 'Output head and tail of input'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/07/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/07/12: start

Todo:
"""

import optparse
import glob
import sys
import collections

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

def HeadTail(args, options):
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

    oOutput = cOutput(options.output)
    if len(lines) <= options.number * 2 + 1:
        for line in lines:
            oOutput.Line(line)
    else:
        for line in lines[0:options.number]:
            oOutput.Line(line)
        oOutput.Line('...')
        for line in lines[-options.number:]:
            oOutput.Line(line)
    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [files]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-n', '--number', type=int, default=10, help='Number of lines')
    oParser.add_option('-o', '--output', default='', help='Output file')
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        HeadTail([''], options)
    else:
        HeadTail(ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
