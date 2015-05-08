#!/usr/bin/env python

__description__ = 'Lookup IP addresses'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2013/02/22'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/01/31: start
  2013/02/17: Added File2Strings, options and LogLine
  2013/02/21: Added file option and FixPipe
  2013/02/22: Replaced option notresolved with nounresolved

Todo:
"""

import optparse
import socket
import sys
import re
import signal

DEFAULT_SEPARATOR = ','
NOTRESOLVED = '<NOTRESOLVED>'

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def LogLine(line, logFileName):
    try:
        outfile = open(logFileName, 'a')
    except:
        return
    try:
        outfile.write(line + '\n')
    except:
        return
    finally:
        outfile.close()

def Output(row, options):
    if options.resultonly:
        line = options.separator.join(row[1:])
    else:
        line = options.separator.join(row)
    print(line)
    if options.output:
        LogLine(line, options.output)

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

class IPv4():
    def __init__(self, argument):
        if type(argument) == type(0l) or type(argument) == type(0):
            self.ipInteger = argument
            self.a = self.ipInteger / 256 ** 3
            self.b = (self.ipInteger - self.a * 256 ** 3) / 256 ** 2
            self.c = (self.ipInteger - self.a * 256 ** 3 - self.b * 256 ** 2) / 256
            self.d = self.ipInteger - self.a * 256 ** 3 - self.b * 256 ** 2 - self.c * 256
        else:
          oMatch = re.match(r'([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)', argument)
          if oMatch:
              for index in range(4):
                  if int(oMatch.groups()[index]) < 0 or int(oMatch.groups()[index]) > 255:
                      return
              self.a = int(oMatch.groups()[0])
              self.b = int(oMatch.groups()[1])
              self.c = int(oMatch.groups()[2])
              self.d = int(oMatch.groups()[3])
              self.ipInteger = self.a * 256 ** 3 + self.b * 256 ** 2 + self.c * 256 + self.d

    def String(self):
        return '%d.%d.%d.%d' % (self.a, self.b, self.c, self.d)

class Subnet():
    def __init__(self, cidr, name=None):
        self.cidr = None
        oMatch = re.match(r'([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)', cidr)
        if oMatch:
            for index in range(4):
                if int(oMatch.groups()[index]) < 0 or int(oMatch.groups()[index]) > 255:
                    return
            if int(oMatch.groups()[4]) < 0 or int(oMatch.groups()[4]) > 32:
                return
            self.cidr = cidr
            self.name = name
            self.prefix = int(oMatch.groups()[4])

            ip = 0
            for index in range(4):
                ip += int(oMatch.groups()[index]) * 256 ** (3 - index)
            prefixmask = (2 ** self.prefix - 1) * 2 ** (32 - self.prefix)
            ipStart = ip & prefixmask
            ipEnd = ipStart + 2 ** (32 - self.prefix) - 1
            self.oIPv4Start = IPv4(ipStart)
            self.oIPv4End = IPv4(ipEnd)

    def Inside(self, oIPv4):
        return oIPv4.ipInteger >= self.oIPv4Start.ipInteger and oIPv4.ipInteger <= self.oIPv4End.ipInteger

def Lookup(ip, options):
    try:
        Output([ip, socket.gethostbyaddr(ip)[0]], options)
    except KeyboardInterrupt:
        print('Interrupted by user')
        sys.exit()
    except:
        if not options.nounresolved:
            Output([ip, NOTRESOLVED], options)

def ClearFile(filename):
    try:
        f = open(filename, 'w')
    except:
        return None
    finally:
        f.close()

def Lookups(arguments, options):
    FixPipe()
    if options.output:
        ClearFile(options.output)
    if options.headers:
        Output(['IP', 'Host'], options)
    if arguments == ['']:
        fIn = sys.stdin
        for line in [line.strip('\n') for line in fIn.readlines()]:
            Lookup(line, options)
        fIn.close()
    else:
        for argument in arguments:
            if options.file:
                expressions = File2Strings(argument)
            else:
                expressions = [argument]
            for expression in expressions:
                oSubnet = Subnet(expression)
                if oSubnet.cidr == None:
                    Lookup(expression, options)
                else:
                    for ipInteger in range(oSubnet.oIPv4Start.ipInteger, oSubnet.oIPv4End.ipInteger + 1):
                        Lookup(IPv4(ipInteger).String(), options)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [IP|Subnet|file] ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-n', '--nounresolved', action='store_true', default=False, help='Only produce output result when IP is resolved')
    oParser.add_option('-o', '--output', help='Write output to file')
    oParser.add_option('-s', '--separator', default=DEFAULT_SEPARATOR, help='Separator character to use for output (default separator character is %s)' % DEFAULT_SEPARATOR)
    oParser.add_option('-H', '--headers', action='store_true', default=False, help='Add header to output')
    oParser.add_option('-f', '--file', action='store_true', default=False, help='Interpret the argument as a file')
    oParser.add_option('-r', '--resultonly', action='store_true', default=False, help='Only output the result')
    (options, args) = oParser.parse_args()

    if len(args) == 0 and options.file:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        Lookups([''], options)
    else:
        Lookups(args, options)

if __name__ == '__main__':
    Main()
