#!/usr/bin/env python

__description__ = 'Tool to monitor new items'
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2024/04/24'

"""
History:
  2012/12/17: start
  2015/08/20: added option -r, -e, -l
  2015/08/24: added option -o, -s
  2015/11/03: fix to support old database format
  2015/11/12: added man option
  2017/11/11: fix for Python 3
  2017/12/30: added option -n
  2018/07/15: 0.0.2 added option -a
  2018/07/20: continued action with function ExecuteAction
  2022/11/20: continued action
  2022/12/17: 0.0.3 MESSAGE2; option exportvanished
  2022/12/19: added --logsame
  2023/05/03: 0.0.4 added --dumpformat
  2024/04/24: updated man

Todo:
  add subprocess.Popen as action option
"""

import optparse
import pickle
import sys
import glob
import time
import collections
import textwrap
import os
import binascii
import datetime
import re

QUOTE = '"'

def PrintManual():
    manual = '''
Manual:

what-is-new is a tool to monitor new items. You give it a name of a database and one or more text files, and it will return all lines in the text files that are new: these are lines that were not seen before, i.e. which are not in the database.
When you run what-is-new for the first time, all lines will be outputted because they are all new (not in the database). But after that initial run only new lines will be outputted.
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
Changes to the database can be written to a log file by using option -l or -L.
With -l, the log file is written in the current directory and the name is what-is-new-DATABASE-DATE-TIME.log. So it's a different log file for each execution.
With -L, the log file is written in the current directory and the name is what-is-new-DATABASE.log. So it's always the same log file for each execution.

All the lines in a database can be dumped with option -d.
They appear as ordered in the database.
To change the order, use option -D --dumpformat.
--dumpformat youngest:first orders the lines by first submission timestamp, from young to old.
--dumpformat oldest:first orders the lines by first submission timestamp, from old to young.
--dumpformat youngest:last orders the lines by last submission timestamp, from young to old.
--dumpformat oldest:last orders the lines by last submission timestamp, from old to young.
The number of dumped lines can be limited by adding a number to the dumpformat value, like this:
--dumpformat youngest:first:number.
For example, --dumpformat oldest:first:5 will dump the 5 oldest lines based on their first submission timestamp.

The database can also be exported as a CSV file including timestamps (local time) using option -e.
Example:
Key;First;Last;Count
A;20150821-110332;20150821-110332;1

The separator for the CSV file is ; by default, but can be chosen with option -s.

Option -E (--exportvanished) is like option -e, but you have to provide a duration. All lines that have not been seen for a period longer than the duration, are exported (same format as -e).
Lines that have been seen within the duration, are not exported.
The duration can be expressed in seconds (with or without suffix s, like 10 or 10s), minutes (with suffix m, 10m), hours (with suffix h, 10h) or days (with suffix d, 10d).

Option -a (action) can be used to provide a command that has to be executed (via os.system) when new items are found. Strings WHATISNEW_MESSAGE1, WHATISNEW_QUOTED_MESSAGE1 and WHATISNEW_BASE64_MESSAGE1 (case-sensitive), when present in the command, will be replaced by a small status string: the number of new items and the first new item. Remark that WHATISNEW_MESSAGE1 contains space characters and that you may want to quote/escape this. WHATISNEW_QUOTED_MESSAGE1 is exactly the same as WHATISNEW_MESSAGE1, but surrounded by double-quotes. WHATISNEW_BASE64_MESSAGE1 is exactly the same as WHATISNEW_MESSAGE1, but BASE64 encoded. Option action can be used to send an email, for example, when new items are found.
String WHATISNEW_BASE64_MESSAGE2 will be replaced by the BASE64 encoding of a string with newlines. The first line is the number of items, followed by all the items. To limit the number of items, append a number to the end of WHATISNEW_BASE64_MESSAGE2_, like this: WHATISNEW_BASE64_MESSAGE2_5. This will limit the list of items to 5 items.
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

def NowUTCISO():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def Basename(basename):
    return 'what-is-new-' + basename

def PickleFilename(basename):
    return Basename(basename) + '.pkl'

def LogFilenameTimestamped(basename):
    return Basename(basename) + '-' + Timestamp() + '.log'

def LogFilename(basename):
    return Basename(basename) + '.log'

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

def ParseMessage2(action):
    oMatch = re.search(r'WHATISNEW_BASE64_MESSAGE2(_?[0-9]*)', action)
    if oMatch != None:
        if len(oMatch.groups()) >= 1:
            if oMatch.groups()[0] == '':
                return True, oMatch.group(), False, None
            if len(oMatch.groups()[0]) > 1 and oMatch.groups()[0].startswith('_'):
                return True, oMatch.group(), True, int(oMatch.groups()[0][1:])
    return False, None, None, None

def ParseDuration(arg):
# valid inputs: 60, 36s, 5m, 2h, 7d
    if arg == '':
        return
    elif arg.endswith('s'):
        delay = int(arg[:-1])
    elif arg.endswith('m'):
        delay = int(arg[:-1]) * 60
    elif arg.endswith('h'):
        delay = int(arg[:-1]) * 60 * 60
    elif arg.endswith('d'):
        delay = int(arg[:-1]) * 60 * 60 * 24
    else:
        delay = int(arg)
    return delay


def ExecuteAction(options, fLog, newLines):
    action = options.action
    message2Found, message2String, message2IntegerFound, message2Intener = ParseMessage2(action)
    if message2Found:
        messageList = ['%d new item(s)' % len(newLines)]
        if message2IntegerFound:
            messageList.extend(newLines[:message2Intener])
        else:
            messageList.extend(newLines)
        messageList.append('')
        message = '\n'.join(messageList)
        action = action.replace(message2String, binascii.b2a_base64(message.encode('latin')).decode('latin'))
    else:
        line = '%d new item(s) %s' % (len(newLines), newLines[0])
        action = action.replace('WHATISNEW_MESSAGE1', line)
        action = action.replace('WHATISNEW_QUOTED_MESSAGE1', '"' + line + '"')
        action = action.replace('WHATISNEW_BASE64_MESSAGE1', binascii.b2a_base64(line.encode('latin')).decode('latin'))
    if fLog != None:
        fLog.write('%s Launching action: %s\n' % (NowUTCISO(), action))
    exitcode = os.system(action)
    if fLog != None:
        fLog.write('%s Action exicode: %d\n' % (NowUTCISO(), exitcode))

def OrderKeys(dDatabase, dumpformat):
    if dumpformat == '':
        keys = list(dDatabase.keys())
        maximum = None
    else:
        parameters = dumpformat.split(':')
        if len(parameters) == 1 or len(parameters) > 3:
            raise Exception('Unknown dumpformat: %s' % dumpformat)
        else:
            if len(parameters) == 2:
                maximum = None
            else:
                maximum = int(parameters[2])
            order = parameters[0]
            field = parameters[1]

        if field == 'first':
            index = 0
        elif field == 'last':
            index = 1
        else:
            raise Exception('Unknown dumpformat: %s' % dumpformat)

        if order == 'youngest':
            reversed = True
        elif order == 'oldest':
            reversed = False
        else:
            raise Exception('Unknown dumpformat: %s' % dumpformat)

        data = sorted([[value[index], key] for key, value in dDatabase.items()], reverse=reversed)
        keys = [item[1] for item in data]
    return keys[:maximum]

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
        for key in OrderKeys(dDatabase, options.dumpformat):
            Print(key, fOut)
    elif options.export:
        Print(MakeCSVLine(('Key', 'First', 'Last', 'Count'), options.separator, QUOTE), fOut)
        for key, values in dDatabase.items():
            Print(MakeCSVLine((key, Timestamp(values[0]), Timestamp(values[1]), values[2]), options.separator, QUOTE), fOut)
    elif options.exportvanished:
        now = time.time()
        duration = ParseDuration(options.exportvanished)
        Print(MakeCSVLine(('Key', 'First', 'Last', 'Count'), options.separator, QUOTE), fOut)
        for key, values in dDatabase.items():
            if now - values[1] >= duration:
                Print(MakeCSVLine((key, Timestamp(values[0]), Timestamp(values[1]), values[2]), options.separator, QUOTE), fOut)
    else:
        if options.log:
            fLog = open(LogFilenameTimestamped(database), 'a')
        elif options.logsame:
            fLog = open(LogFilename(database), 'a')
        else:
            fLog = None
        newLines = []
        for file in files:
            if file == '':
                fIn = sys.stdin
            else:
                fIn = open(file, 'r')
            if fLog != None:
                fLog.write('File: %s (%s)\n' % (file, NowUTCISO()))
            for line in [x.strip('\n\r') for x in fIn.readlines()]:
                if line in dDatabase:
                    if dDatabase[line] == 1: # handle old database format
                        dDatabase[line] = [now, now, 1]
                    else:
                        dDatabase[line][1] = now
                        dDatabase[line][2] += 1
                else:
                    Print(line, fOut)
                    dDatabase[line] = [now, now, 1]
                    newLines.append(line)
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

        if not options.check:
            Serialize({'database': dDatabase}, database + IFF(options.newdb, '-new', ''))

        if len(newLines) > 0 and options.action != '':
            ExecuteAction(options, fLog, newLines)

        if fLog != None:
            fLog.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] database [files]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-c', '--check', action='store_true', default=False, help='just check, do not store')
    oParser.add_option('-n', '--newdb', action='store_true', default=False, help='create a new database, do not update existing')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='dump all stored items')
    oParser.add_option('-e', '--export', action='store_true', default=False, help='export all stored items with timestamps')
    oParser.add_option('-E', '--exportvanished', type=str, default='', help='like option -e, but only for entries that have not been seen at least as long as the given duration')
    oParser.add_option('-r', '--remove', action='store_true', default=False, help='remove all entries present in the database and not present in the file(s)')
    oParser.add_option('-l', '--log', action='store_true', default=False, help='log adding to/removing from the database (timestamped file)')
    oParser.add_option('-L', '--logsame', action='store_true', default=False, help='log adding to/removing from the database')
    oParser.add_option('-o', '--output', help='output to file')
    oParser.add_option('-a', '--action', type=str, default='', help='action (command) to take when new items were found')
    oParser.add_option('-s', '--separator', default=';', help='separator character (default ;)')
    oParser.add_option('-D', '--dumpformat', type=str, default='', help='order:count to use when dumping possible values: youngest, oldest (default None)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 1:
        if options.dump or options.export or options.exportvanished:
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
