#!/usr/bin/env python

__description__ = 'count unique items'
__author__ = 'Didier Stevens'
__version__ = '0.1.0'
__date__ = '2014/08/04'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2010/09/08: start
  2012/08/01: refactor
  2013/03/17: 0.0.3: added option n
  2013/08/29: added option s, S, H, p, i and o
  2013/09/01: added pickle
  2013/11/21: added @file
  2014/07/29: 0.1.0: speed and memory optimization, added option -b
  2014/08/03: added options inputseparator, outputseparator, rank
  2014/08/04: added option lowercase

Todo:
"""

import optparse
import glob
import sys
import pickle
import os
import collections

PICKLE_FILE = 'count.pkl'

def Serialize(object, filename=PICKLE_FILE):
    try:
        fPickle = open(filename, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize(filename=PICKLE_FILE):
    if os.path.isfile(filename):
        try:
            fPickle = open(filename, 'rb')
        except:
            return None
        try:
            object = pickle.load(fPickle)
        except:
            return None
        finally:
            fPickle.close()
        return object
    else:
        return None

class cOutput():
    def __init__(self, filename=None, bothoutputs=False):
        self.filename = filename
        self.bothoutputs = bothoutputs
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if self.f:
            self.f.write(line + '\n')
        if not self.f or self.bothoutputs:
            print(line)

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def PrintDictionary(dCount, sortDescending, sortKeys, totals, nocounts, separator, header, percentage, rank, outputfile, bothoutputs):
    oOutput = cOutput(outputfile, bothoutputs)

    if header:
        if nocounts:
            line = 'Element'
        else:
            line = 'Element%sCount' % separator
        if rank:
            line = 'Rank%s%s' % (separator, line)
        if percentage:
            line = '%s%sCount%%' % (line, separator)
        oOutput.Line(line)

    if rank:
        if sortDescending:
            ranknumber = 1
        else:
            ranknumber = len(dCount.keys())
    if percentage or totals:
        sumValues = sum(dCount.values())
    listCount = dCount.items()
    if sortKeys:
        index = 0
    else:
        index = 1
    listCount.sort(lambda x, y:cmp(x[index], y[index]), reverse=sortDescending)
    for key, value in listCount:
        if nocounts:
            line = key
        else:
            line = '%s%s%d' % (key, separator, value)
        if rank:
            line = '%d%s%s' % (ranknumber, separator, line)
            if sortDescending:
                ranknumber += 1
            else:
                ranknumber -= 1
        if percentage:
            line = '%s%s%.2f%%' % (line, separator, float(value) / sumValues * 100.0)
        oOutput.Line(line)
    if totals:
        oOutput.Line('uniques%s%d' % (separator, len(dCount.keys())))
        oOutput.Line('total%s%d' % (separator, sumValues))

    oOutput.Close()

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

def CountDictionary(args, options):
    dCount = {}
    if options.resume:
        dData = DeSerialize(options.resume)
        if dData != None and 'dCount' in dData:
            dCount = dData['dCount']
    if args != ['']:
        args = ExpandFilenameArguments(args)
    for file in args:
        if file == '':
            fIn = sys.stdin
        else:
            fIn = open(file, 'r')
        for line in fIn:
            line = line.strip('\n')
            if options.lowercase:
                line = line.lower()
            if options.split:
                elements = [x for x in line.split(options.inputseparator) if x != '']
            else:
                elements = [line]
            for element in elements:
                if options.ignore == '' or options.ignore != element:
                    if not element in dCount:
                        dCount[element] = 0
                    dCount[element] += 1
        fIn.close()
    if options.export:
        Serialize({'dCount': dCount}, options.export)
    return dCount

def Count(args, options):
    PrintDictionary(CountDictionary(args, options), options.descending, options.keys, options.totals, options.nocounts, options.outputseparator, options.header, options.percentage, options.rank, options.output, options.bothoutputs)

def Main():
    moredesc = '''

files:
wildcards are supported
@file: run command on each file listed in the text file specified

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [files ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-d', '--descending', action='store_true', default=False, help='sort descending')
    oParser.add_option('-k', '--keys', action='store_true', default=False, help='sort on keys in stead of counts')
    oParser.add_option('-t', '--totals', action='store_true', default=False, help='print totals')
    oParser.add_option('-n', '--nocounts', action='store_true', default=False, help="don't display the counters")
    oParser.add_option('-s', '--split', action='store_true', default=False, help="split lines")
    oParser.add_option('-l', '--lowercase', action='store_true', default=False, help='convert all input to lowercase before counting')
    oParser.add_option('-I', '--inputseparator', default=',', help='input separator (default ,)')
    oParser.add_option('-O', '--outputseparator', default=',', help='output separator (default ,)')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='start with a header')
    oParser.add_option('-p', '--percentage', action='store_true', default=False, help='include percentage')
    oParser.add_option('-R', '--rank', action='store_true', default=False, help='include rank')
    oParser.add_option('-i', '--ignore', default='', help='element to ignore')
    oParser.add_option('-o', '--output', default='', help='output file')
    oParser.add_option('-b', '--bothoutputs', action='store_true', default=False, help='if used together with option o, output is also displayed')
    oParser.add_option('-r', '--resume', default='', help='resume from saved data')
    oParser.add_option('-e', '--export', default='', help='export: save data')
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        args = ['']
    Count(args, options)

if __name__ == '__main__':
    Main()
