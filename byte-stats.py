#!/usr/bin/env python

__description__ = 'Calculate byte statistics'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/10/17'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/10/25: start
  2014/10/26: refactoring
  2015/10/17: added buckets and properties

Todo:
"""

import optparse
import glob
import sys
import collections
import os
import math
import string
import textwrap

def PrintManual():
    manual = '''
Manual:

To be written
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

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
    return sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def GenerateLine(prefix, counter, sumValues, buckets, index, options):
    line = '%-18s%9d %6.2f%%' % (prefix + ':', counter, float(counter) / sumValues * 100.0)
    if len(buckets) > 0:
        value = min([properties[index] for position, properties in buckets])
        line += ' %9d %6.2f%%' % (value, float(value) / float(options.bucket) * 100.0)
        if len(buckets) > 1:
            value = max([properties[index] for position, properties in buckets])
            line += ' %9d %6.2f%%' % (value, float(value) / float(options.bucket) * 100.0)
    return line

def ByteStats(args, options):
    countBytes = 0
    dPrevalence = {iter: 0 for iter in range(0x100)}
    dPrevalenceBucket = {iter: 0 for iter in range(0x100)}
    buckets = []
    if args != ['']:
        args = ExpandFilenameArguments(args)
    for file in args:
        if file == '':
            fIn = sys.stdin
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        else:
            fIn = open(file, 'rb')
        for char in fIn.read():
            dPrevalence[ord(char)] += 1
            dPrevalenceBucket[ord(char)] += 1
            countBytes += 1
            if countBytes % options.bucket == 0:
                buckets.append([countBytes - options.bucket, CalculateByteStatistics(dPrevalenceBucket)])
                dPrevalenceBucket = {iter: 0 for iter in range(0x100)}
        if fIn != sys.stdin:
            fIn.close()

    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    if options.list:
        dProperties = {'e': 1, 'n': 2, 'c': 3, 'w': 4, 'p': 5, 'h': 6}
        if options.property not in dProperties:
            print('Unknown property: %s' % options.property)
            return
        index = dProperties[options.property]
        if options.property == 'e':
            format = '0x%08x %f'
        else:
            format = '0x%08x %9d'
        for position, properties in buckets:
            print(format % (position, properties[index]))
    else:
        listCount = dPrevalence.items()
        if options.keys:
            index = 0
        else:
            index = 1
        listCount.sort(lambda x, y:cmp(x[index], y[index]), reverse=options.descending)
        lineCounter = 0
        dotsPrinted = False
        for key, value in listCount:
            if options.all or lineCounter < 5 or lineCounter > 250:
                line = '0x%02x %s %9d %6.2f%%' % (key, IFF(key >= 0x20 and key < 0x7F, chr(key), ' '), value, float(value) / sumValues * 100.0)
                print(line)
            elif not dotsPrinted:
                print('...')
                dotsPrinted = True
            lineCounter +=  1
        line = 'Size: %d' % sumValues
        if len(buckets) > 0:
            line += '  Bucket size: %d  Bucket count: %d' % (options.bucket, len(buckets))
        print(line)
        line = 'Entropy: %f' % entropy
        if len(buckets) > 0:
            line += '  %f' % min([properties[1] for position, properties in buckets])
            if len(buckets) > 1:
                line += '  %f' % max([properties[1] for position, properties in buckets])
        print(line)
        print(GenerateLine('NULL bytes', countNullByte, sumValues, buckets, 2, options))
        print(GenerateLine('Control bytes', countControlBytes, sumValues, buckets, 3, options))
        print(GenerateLine('Whitespace bytes', countWhitespaceBytes, sumValues, buckets, 4, options))
        print(GenerateLine('Printable bytes', countPrintableBytes, sumValues, buckets, 5, options))
        print(GenerateLine('High bytes', countHighBytes, sumValues, buckets, 6, options))

def Main():
    moredesc = '''

files:
wildcards are supported
@file: run command on each file listed in the text file specified

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [files ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-d', '--descending', action='store_true', default=False, help='sort descending')
    oParser.add_option('-k', '--keys', action='store_true', default=False, help='sort on keys in stead of counts')
    oParser.add_option('-b', '--bucket', type=int, default=10240, help='use bucket as given size (default is 10240)')
    oParser.add_option('-l', '--list', action='store_true', default=False, help='print list of bucket property')
    oParser.add_option('-p', '--property', default='e', help='property to analyze: encwph')
    oParser.add_option('-a', '--all', action='store_true', default=False, help='Print all byte stats')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        args = ['']
    ByteStats(args, options)

if __name__ == '__main__':
    Main()
