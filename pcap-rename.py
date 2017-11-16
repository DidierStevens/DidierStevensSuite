#!/usr/bin/env python

__description__ = 'Rename pcap files with timestamp of the first packet'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2017/11/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/10/03: start
  2017/11/16: added support for big-endian files

Todo:
"""

import optparse
import glob
import collections
import time
import os
import textwrap

def PrintManual():
    manual = '''
Manual:

pcap-rename.py is a program to rename pcap files with a timestamp of the first packet in the pcap file.

The first argument is a template of the new filename. Use %% as a placeholder for the timestamp. Don't forget the .pcap extension.

The next arguments are the pcap files to be renamed.
You can provide one or more pcap files, use wildcards (*.pcap) and use @file.
@file: file is a text file containing filenames. Each file listed in the text file is processed.

Example to rename pcap files:
pcap-rename.py server-%%.pcap *.pcap

Output:
Renamed: capture1.pcap -> server-20140416-184037-926493.pcap
Renamed: capture2.pcap -> server-20140417-114252-700036.pcap
Renamed: capture3.pcap -> server-20140419-052202-911011.pcap
Renamed: capture4.pcap -> server-20140424-065625-868672.pcap

Use option -n to view the result without actually renaming the pcap files.

This program does not support .pcapng files (yet).
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

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def File2Bytes(filename, size=None):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        if size == None:
            return f.read()
        else:
            return f.read(size)
    except:
        return None
    finally:
        f.close()

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

def StringToUnsignedIntegerBigEndian(data):
    number = 0
    for c in data:
        number = number * 0x100 + ord(c)
    return number

def StringToUnsignedIntegerLittleEndian(data):
    return StringToUnsignedIntegerBigEndian(data[::-1])

# S stands for Slice
def S(data, index, size):
    return data[index:index + size]

def PcapRename(templateFilename, filenames, options):
    for filename in ExpandFilenameArguments(filenames):
        data = File2Bytes(filename, 32)
        if len(data) < 32:
            print('File too small: %s' % filename)
            continue
        if S(data, 0, 4) == '\xD4\xC3\xB2\xA1':
            if S(data, 4, 4) != '\x02\x00\x04\x00':
                print('Unexpected version number: %s' % filename)
                continue
            newFilename = os.path.join(os.path.dirname(filename), templateFilename.replace('%%', '%s-%06d' % (Timestamp(StringToUnsignedIntegerLittleEndian(S(data, 24, 4))), StringToUnsignedIntegerLittleEndian(S(data, 28, 4)))))
        elif S(data, 0, 4) == '\xA1\xB2\xC3\xD4':
            if S(data, 4, 4) != '\x00\x02\x00\x04':
                print('Unexpected version number: %s' % filename)
                continue
            newFilename = os.path.join(os.path.dirname(filename), templateFilename.replace('%%', '%s-%06d' % (Timestamp(StringToUnsignedIntegerBigEndian(S(data, 24, 4))), StringToUnsignedIntegerBigEndian(S(data, 28, 4)))))
        else:
            print('Unexpected magic number: %s' % filename)
            continue
        try:
            if filename != newFilename:
                if os.path.exists(newFilename):
                    print('Warning file already exists: %s -> %s' % (filename, newFilename))
                else:
                    if options.norename:
                        print('To be renamed: %s -> %s' % (filename, newFilename))
                    else:
                        os.rename(filename, newFilename)
                        print('Renamed: %s -> %s' % (filename, newFilename))
        except BaseException as e:
            print('Error renaming: %s -> %s - %s' % (filename, newFilename, e))

def Main():
    moredesc = '''

Arguments:
new-filename-template: use %% as a placeholder for the timestamp
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] new-filename-template [@]file ...\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-n', '--norename', action='store_true', default=False, help='do not rename the files, just report')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='print manual')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) < 2:
        oParser.print_help()
        return
    else:
        PcapRename(args[0], args[1:], options)

if __name__ == '__main__':
    Main()
