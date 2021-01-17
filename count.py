#!/usr/bin/env python

__description__ = 'count unique items'
__author__ = 'Didier Stevens'
__version__ = '0.3.0'
__date__ = '2021/01/15'

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
  2017/05/27: 0.1.1: new options -z --ranktop --rankbottom
  2017/06/02: 0.2.0: added support for sqlite3 with option -c
  2017/07/27: added option where
  2021/01/15: 0.3.0 Python 3

Todo:
"""

import optparse
import glob
import sys
import pickle
import os
import collections
import sqlite3

bPython3 = sys.version_info[0] > 2

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

def MyCmp(a, b):
    return (a > b) - (a < b)

def cmp_to_key(mycmp):
    'Convert a cmp= function into a key= function'
    class K:
        def __init__(self, obj, *args):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0
        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0
        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0
        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0
    return K

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

def PrintDictionary(dCount, options):
    oOutput = cOutput(options.output, options.bothoutputs)

    if options.header:
        if options.nocounts:
            line = 'Element'
        else:
            line = 'Element%sCount' % options.outputseparator
        if options.rank:
            line = 'Rank%s%s' % (options.outputseparator, line)
        if options.percentage:
            line = '%s%sCount%%' % (line, options.outputseparator)
        oOutput.Line(line)

    uniques = len(dCount.keys())
    if options.descending:
        ranknumber = 1
    else:
        ranknumber = uniques
    if options.percentage or options.totals:
        sumValues = sum(dCount.values())
    listCount = dCount.items()
    if options.keys:
        index = 0
    else:
        index = 1
        
    if bPython3:
        listCount = sorted(listCount, key=cmp_to_key(lambda x, y:MyCmp(x[index], y[index])), reverse=options.descending)
    else:
        listCount.sort(lambda x, y:cmp(x[index], y[index]), reverse=options.descending)
    for key, value in listCount:
        if options.nocounts:
            line = key
        else:
            line = '%s%s%d' % (key, options.outputseparator, value)
        if options.rank:
            line = '%d%s%s' % (ranknumber, options.outputseparator, line)
        if options.percentage:
            line = '%s%s%.2f%%' % (line, options.outputseparator, float(value) / sumValues * 100.0)
        if options.ranktop == None and options.rankbottom == None:
            oOutput.Line(line)
        elif options.ranktop != None:
            if ranknumber <= options.ranktop:
                oOutput.Line(line)
        elif options.rankbottom != None:
            if uniques - ranknumber + 1 <= options.rankbottom:
                oOutput.Line(line)
        if options.descending:
            ranknumber += 1
        else:
            ranknumber -= 1
    if options.totals:
        oOutput.Line('uniques%s%d' % (options.outputseparator, uniques))
        oOutput.Line('total%s%d' % (options.outputseparator, sumValues))

    oOutput.Close()

def PrintSqlite3(connection, options):
    oOutput = cOutput(options.output, options.bothoutputs)

    if options.header:
        if options.nocounts:
            line = 'Element'
        else:
            line = 'Element%sCount' % options.outputseparator
        if options.rank:
            line = 'Rank%s%s' % (options.outputseparator, line)
        if options.percentage:
            line = '%s%sCount%%' % (line, options.outputseparator)
        oOutput.Line(line)

#    for row in connection.execute('select * from count order by counter desc limit 10'):

    if options.where != '':
        where = ' where ' + options.where
    else:
        where = ''
    uniques = connection.execute('select count(*) from count' + where).fetchone()[0]
    if options.descending:
        ranknumber = 1
    else:
        ranknumber = uniques
    if options.percentage or options.totals:
        sumValues = connection.execute('select sum(counter) from count' + where).fetchone()[0]
    if options.keys:
        selectStatement = 'select * from count' + where + ' order by key'
    else:
        selectStatement = 'select * from count' + where + ' order by counter'
    if options.descending:
        selectStatement += ' desc'
    for key, value in connection.execute(selectStatement):
        if options.nocounts:
            line = key
        else:
            line = '%s%s%d' % (key, options.outputseparator, value)
        if options.rank:
            line = '%d%s%s' % (ranknumber, options.outputseparator, line)
        if options.percentage:
            line = '%s%s%.2f%%' % (line, options.outputseparator, float(value) / sumValues * 100.0)
        if options.ranktop == None and options.rankbottom == None:
            oOutput.Line(line)
        elif options.ranktop != None:
            if ranknumber <= options.ranktop:
                oOutput.Line(line)
        elif options.rankbottom != None:
            if uniques - ranknumber + 1 <= options.rankbottom:
                oOutput.Line(line)
        if options.descending:
            ranknumber += 1
        else:
            ranknumber -= 1
    if options.totals:
        oOutput.Line('uniques%s%d' % (options.outputseparator, uniques))
        oOutput.Line('total%s%d' % (options.outputseparator, sumValues))

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
                        dCount[element] = 1
                    else:
                        dCount[element] += 1
        if fIn != sys.stdin:
            fIn.close()
    if options.export:
        Serialize({'dCount': dCount}, options.export)
    return dCount

def CountAndPrintSqlite3(args, options):
    connection = sqlite3.connect(options.countingmethod)
    connection.text_factory = str
    connection.execute('pragma synchronous=off')
    connection.execute('create table if not exists count (key text primary key, counter integer)')

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
                    try:
                        connection.execute('insert into count values (?, ?)', (element, 1))
                    except sqlite3.IntegrityError:
                        connection.execute('update count set counter = counter + 1 where key = ?', (element, ))
        if fIn != sys.stdin:
            fIn.close()

    PrintSqlite3(connection, options)

    if options.countingmethod != '' and options.countingmethod != ':memory:':
        connection.commit()
    connection.close()

def Count(args, options):
    if options.countingmethod == ':dictionary:':
        PrintDictionary(CountDictionary(args, options), options)
    else:
        CountAndPrintSqlite3(args, options)

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
    oParser.add_option('--ranktop', type=int, help='output only top ranked')
    oParser.add_option('--rankbottom', type=int, help='output only bottom ranked')
    oParser.add_option('-i', '--ignore', default='', help='element to ignore')
    oParser.add_option('-o', '--output', default='', help='output file')
    oParser.add_option('-b', '--bothoutputs', action='store_true', default=False, help='if used together with option o, output is also displayed')
    oParser.add_option('-r', '--resume', default='', help='resume from saved data')
    oParser.add_option('-e', '--export', default='', help='export: save data')
    oParser.add_option('-z', '--zeroinput', action='store_true', default=False, help='no input to process')
    oParser.add_option('-c', '--countingmethod', default=':dictionary:', help='internal method used to count: :dictionary: or sqlite3 database name: :memory:, '', ...')
    oParser.add_option('-w', '--where', default='', help='where clause for sqlite3 database')
    (options, args) = oParser.parse_args()

    if options.zeroinput:
        args = []
    elif len(args) == 0:
        args = ['']
    Count(args, options)

if __name__ == '__main__':
    Main()
