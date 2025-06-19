#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Save binary data while piping it from stdin to stdout. Like the tee command, but plus.'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2025/06/19'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/12/18: start from binary template
  2025/06/19: 0.0.2 added option -t

Todo:

"""

import optparse
import sys
import os
import textwrap
import hashlib
import datetime

DEFAULT_LOG_FILENAME = 'teeplus.log'
DEFAULT_EXTENSION = '.vir'

def PrintManual():
    manual = r'''
Manual:

This tool reads binary data from stdin and outputs it unmodified to stdout.
The binary data is also written to disk with filename SHA256%s, where SHA256 is the SHA256 hash of the data.
The default extension (%s) can be changed with option -e.
At each execution, a line is written to a logfile with name specified via option -l.
This log line consists of 4 comma-separated fields: iso-timestamp, data length, sha56 hash of the binary data and error if writing data failed.
The default log filename is "%s".
The log filename can also be generated with option -g. The string provided with option -g is a keyword used in the log filename generation.
For example, "-g malware" generates this log filename: "teeplus-malware.log".
Option -n can be used to prevent that the stdin input is piped to stdout.
Use this option if no further processing is needed (just logging and storing). Or redirect to /dev/null.
Use option -t to use a timestamp as filename.

''' % (DEFAULT_EXTENSION, DEFAULT_EXTENSION, DEFAULT_LOG_FILENAME)
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

DEFAULT_SEPARATOR = ','
QUOTE = '"'

#not sure if this is still required in Python 3, to be checked
def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def ToString(value):
    if isinstance(value, str):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if len(value) > 1 and value[0] == quote and value[-1] == quote:
        return value
    if separator in value or value == '':
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def NowUTCISO():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def Teeplus(options):
    nowUTCISO = NowUTCISO()

    IfWIN32SetBinary(sys.stdin)
    data = sys.stdin.buffer.read()

    if not options.nooutput:
        IfWIN32SetBinary(sys.stdout)
        sys.stdout.buffer.write(data)

    sha256 = hashlib.sha256(data).hexdigest()

    if options.timestamp:
        filename = nowUTCISO.replace(':', '_')
        if options.generate != '':
            filename = options.generate + '-' + filename
    else:
        filename = sha256
    filename += options.extension
    try:
        with open(filename, 'wb') as fSave:
            fSave.write(data)
    except Exception as e:
        error = e
    else:
        error = ''

    if options.generate != '':
        logFilename = '%s-%s.%s' % (DEFAULT_LOG_FILENAME.split('.')[0], options.generate, DEFAULT_LOG_FILENAME.split('.')[1])
    else:
        logFilename = options.log
    try:
        with open(logFilename, 'a') as fLog:
            fLog.write('%s\n' % MakeCSVLine([nowUTCISO, len(data), sha256, error], DEFAULT_SEPARATOR, QUOTE))
    except:
        pass

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-e', '--extension', type=str, default=DEFAULT_EXTENSION, help='Extension for the saved file (default %s)' % DEFAULT_EXTENSION)
    oParser.add_option('-l', '--log', type=str, default=DEFAULT_LOG_FILENAME, help='Name of log file (default %s)' % DEFAULT_LOG_FILENAME)
    oParser.add_option('-g', '--generate', type=str, default='', help='Keyword to generate logfilename with')
    oParser.add_option('-n', '--nooutput', action='store_true', default=False, help='Do not produce output to stdout')
    oParser.add_option('-t', '--timestamp', action='store_true', default=False, help='Filename is timestamp')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0:
        print('This tool does not take arguments, only options.')
        return

    Teeplus(options)

if __name__ == '__main__':
    Main()
