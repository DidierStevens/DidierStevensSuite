#!/usr/bin/env python

__description__ = 'Tool to monitor new items'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/12/30'

"""
History:
  2012/12/17: start
  2015/08/20: added option -r, -e, -l
  2015/08/24: added option -o, -s
  2015/11/03: fix to support old database format
  2015/11/12: added man option
  2017/11/11: fix for Python 3
  2017/12/30: added option -n

"""

import optparse
import pickle
import sys
import glob
import time
import collections
import textwrap

QUOTE = '"'

def PrintManual():
    manual = '''
Manual:

what-is-new is a tool to monitor new items. You give it a name of a database and one or more text files, and it will return all lines in the text files that are new: these are lines that were not seen before, i.e. which are not in the database.
When you run what-is-new for the first time, all lines will be outputed because they are all new (not in the database). But after that initial run only new lines will be outputed.
The database is a pickle file, created in the current directory. The name of the database is what-is-new-DATABASE.pkl, where DATABASE is the database argument you passed to what-is-new.

Example:

This is the content of file test-1.txt:

1
2
3

C:\Demo>what-is-new.py demo test-1.txt
1
2
3

This is the content of file test-2.txt:

1
2
3
4

C:\Demo>what-is-new.py demo test-2.txt
4

By default output is send to standard output, but can be send to a file with option -o.
To check a file without updating the existing database, use option -c.
To create a new database without updating the existing database, use option -n. This will read database what-is-new-DATABASE.pkl and write database what-is-new-DATABASE-new.pkl.
By default, only new lines are added to the database, no lines are removed. If you want to remove lines from the database that are not present in the files passed to what-is-new, use option -r.
Changes to the database can be written to a log file by using option -l. The log file is written in the current directory and the name is what-is-new-DATABASE-DATE-TIME.log.
All the lines in a database can be dumped with option -d.
The database can also be exported as a CSV file including timestamps (local time) using option -e.
Example:
Key;First;Last;Count
A;20150821-110332;20150821-110332;1

The separator for the CSV file is ; by default, but can be chosen with option -s.

This Python program was developed and tested with Python 2, and also tested with Python 3.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

def Basename(basename):
    return 'what-is-new-' + basename

def PickleFilename(basename):
    return Basename(basename) + '.pkl'

def LogFilename(basename):
    return Basename(basename) + '-' + Timestamp() +'.log'

def Serialize(object, basename):
    pickleFile = PickleFilename(basename)
    try:
        fPickle = open(pickleFile, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize(basename):
    import os.path

    pickleFile = PickleFilename(basename)
    if os.path.isfile(pickleFile):
        try:
            fPickle = open(pickleFile, 'rb')
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

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line +'\n')

def WhatIsNew(database, files, options):
    now = time.time()
    data = DeSerialize(database)
    if data and 'database' in data:
        dDatabase = data['database']
    else:
        dDatabase = {}
    if options.output:
        fOut = open(options.output, 'w')
    else:
        fOut = None
    if options.dump:
        for key in dDatabase.keys():
            Print(key, fOut)
    elif options.export:
        Print(MakeCSVLine(('Key', 'First', 'Last', 'Count'), options.separator, QUOTE), fOut)
        for key, values in dDatabase.items():
            Print(MakeCSVLine((key, Timestamp(values[0]), Timestamp(values[1]), values[2]), options.separator, QUOTE), fOut)
    else:
        if options.log:
            fLog = open(LogFilename(database), 'a')
        else:
            fLog = None
        for file in files:
            if file == '':
                fIn = sys.stdin
            else:
                fIn = open(file, 'r')
            if fLog != None:
                fLog.write('File: %s\n' % file)
            for line in [x.strip('\n') for x in fIn.readlines()]:
                if line in dDatabase:
                    if dDatabase[line] == 1: # handle old database format
                        dDatabase[line] = [now, now, 1]
                    else:
                        dDatabase[line][1] = now
                        dDatabase[line][2] += 1
                else:
                    Print(line, fOut)
                    dDatabase[line] = [now, now, 1]
                    if fLog != None:
                        fLog.write('Added: %s\n' % line)
            fIn.close()

        if options.remove:
            for key, value in list(dDatabase.items()):
                if value[1] < now:
                    del dDatabase[key]
                    if fLog != None:
                        fLog.write('Removed: %s\n' % key)

        if fOut != None:
            fOut.close()

        if fLog != None:
            fLog.close()

        if not options.check:
            Serialize({'database': dDatabase}, database + IFF(options.newdb, '-new', ''))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] database [files]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-c', '--check', action='store_true', default=False, help='just check, do not store')
    oParser.add_option('-n', '--newdb', action='store_true', default=False, help='create a new database, do not update existing')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='dump all stored items')
    oParser.add_option('-e', '--export', action='store_true', default=False, help='export all stored items with timestamps')
    oParser.add_option('-r', '--remove', action='store_true', default=False, help='remove all entries present in the database and not present in the file(s)')
    oParser.add_option('-l', '--log', action='store_true', default=False, help='log adding to/removing from the database')
    oParser.add_option('-o', '--output', help='output to file')
    oParser.add_option('-s', '--separator', default=';', help='separator character (default ;)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 1:
        if options.dump or options.export:
            files = []
        else:
            files = ['']
    elif len(args) < 1:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        return
    else:
        files = ExpandFilenameArguments(args[1:])
    WhatIsNew(args[0], files, options)

if __name__ == '__main__':
    Main()
