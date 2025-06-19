#!/usr/bin/env python

from __future__ import print_function

__description__ = 'IP address tool'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2025/06/14'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2023/08/18: start
  2025/01/17: added ipincidr command
  2025/04/13: continue
  2025/06/14: manual

Todo:
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import os
import ipaddress
import csv

COMMAND_CIDR2IP = 'cidr2ip'
COMMAND_ASN2CIDR = 'asn2cidr'
COMMAND_IPINCIDR = 'ipincidr'
COMMAND_ASO2CIDR = 'aso2cidr'

COMMANDS = [COMMAND_CIDR2IP, COMMAND_ASN2CIDR, COMMAND_IPINCIDR, COMMAND_ASO2CIDR]

ASNFILE = 'GeoLite2-ASN-Blocks-IPv4.csv'

def PrintManual():
    manual = '''
Manual:

4 commands are available: cidr2ip, asn2cidr, ipincidr and aso2cidr.


Command cidr2ip is used to generate IPv4 addresses for the given CIDRs.

Example: myipaddress.py cidr2ip 192.168.0.0/24 10.10.10.0/30

Option -u (--unique) will remove all duplicates from the generated list.

Option -s (--sort) will sort the list.


Command asn2cidr is used to generate a list of IPv4 CIDRs for the given ASNs (autonomous system numbers).

Example: myipaddress.py asn2cidr 100 1234

Output:
100: 12.30.153.0/24 74.123.89.0/24 102.210.158.0/24 192.118.48.0/24 198.180.4.0/22 199.36.118.0/24 199.48.212.0/22 216.225.27.0/24
1234: 132.171.0.0/16 137.96.0.0/16 193.110.32.0/21

Option -q (--quiet) will produce a simple list of CIDRs, nothing more.

Example: myipaddress.py -q asn2cidr 1234

Output:
132.171.0.0/16
137.96.0.0/16
193.110.32.0/21

Option -u (--unique) will remove all duplicates from the generated list.

This command requires CSV file GeoLite2-ASN-Blocks-IPv4.csv to be present in the same folder as script myipaddress.py.
See below for more info.


Command ipincidr is used to generate a list of IPv4 addresses for the text files.

The text files either contain a list of IPv4 addresses or a list of IPv4 CIDRs (it can actually be a mix of both in the same file).
Then the command will produce a list for the given IPv4 addresses that are contained in the given CIDRs.
If a line of the text file contains a / character, it is interpreted as a CIDR, otherwise it is interpreted as a IPv4 address.
CIDRs can also be followed by an ASO with the tab character as separator.

Example: myipaddress.py ipincidr cidrs.txt ipv4s.txt

Option -v (--inverse) will invert the logic: all given IPv4 addresses that are NOT contained in the GIVEN CIDRs are listed.


Command aso2cidr is used to generate a list of IPv4 CIDRs for the given ASOs substrings (autonomous system organisations).

Example: myipaddress.py aso2cidr sans-institute

Output:
SANS-INSTITUTE: 66.35.60.0/24 104.193.44.0/24

Example: myipaddress.py aso2cidr sans-institute amadeus

Output:
SANS-INSTITUTE: 66.35.60.0/24 104.193.44.0/24
Amadeus Data Processing GmbH: 82.150.224.0/21 82.150.248.0/23 168.153.3.0/24 168.153.4.0/22 168.153.8.0/23 168.153.32.0/22 168.153.40.0/22 168.153.64.0/22 168.153.96.0/24 168.153.106.0/24 168.153.109.0/24 168.153.110.0/23 168.153.144.0/22 168.153.160.0/22 171.17.128.0/18 171.17.255.0/24 185.165.8.0/23 193.23.186.0/24 193.24.37.0/24 195.27.162.0/23 213.70.140.0/24
Amadeus Soluciones Tecnologicas S.A.: 94.142.200.0/21
Amadeus is an international computer reservations system. A subsidary is in Bangalore and t: 168.153.1.0/24
Amadeus India Pvt.Ltd.: 202.0.109.0/24
Amadeus India: 203.89.132.0/24

Option -q (--quiet) will produce a simple list of CIDRs, nothing more.

Example: myipaddress.py -q aso2cidr sans-institute

Output:
66.35.60.0/24
104.193.44.0/24

Option -e (--extra) will add the ASO (with tab character as separator).

Example: myipaddress.py -q -e aso2cidr sans-institute

Output:
66.35.60.0/24	SANS-INSTITUTE
104.193.44.0/24	SANS-INSTITUTE

Option -u (--unique) will remove all duplicates from the generated list.

This command requires CSV file GeoLite2-ASN-Blocks-IPv4.csv to be present in the same folder as script myipaddress.py.
See below for more info.


File GeoLite2-ASN-Blocks-IPv4.csv can be obtained for free by creating an account on maxmind.com and then download database known as:
GeoLite ASN: CSV Format 
It's a ZIP file that contains file GeoLite2-ASN-Blocks-IPv4.csv.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

DEFAULT_SEPARATOR = ','
QUOTE = '"'

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

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

class cVariables():
    def __init__(self, variablesstring='', separator=DEFAULT_SEPARATOR):
        self.dVariables = {}
        if variablesstring == '':
            return
        for variable in variablesstring.split(separator):
            name, value = VariableNameValue(variable)
            self.dVariables[name] = value

    def SetVariable(self, name, value):
        self.dVariables[name] = value

    def Instantiate(self, astring):
        for key, value in self.dVariables.items():
            astring = astring.replace('%' + key + '%', value)
        return astring

class cOutput():
    def __init__(self, filenameOption=None):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

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

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])

def FileAppDirectory(filename):
    return os.path.join(GetScriptPath(), filename)
    
def ISASNFileMissing():
    if os.path.exists(FileAppDirectory(ASNFILE)):
        return False
    print("File %s is missing, it's a free CSV file available from Maxmind (GeoLite2 ASN Database)" % ASNFILE)
    return True

def ASN2CIDR(args, oOutput, options):

    if ISASNFileMissing():
        return
    oCSVReader = csv.reader(open(FileAppDirectory(ASNFILE), 'r', encoding='utf8'))

    dASNs = {}
    for row in oCSVReader:
        if row[1] in args:
            if not row[1] in dASNs:
                dASNs[row[1]] = []
            dASNs[row[1]].append(row[0])
    if options.quiet:
        allranges = []

        for asn, ranges in dASNs.items():
            allranges.extend(ranges)

        if options.uniques:
            allranges = list(set(allranges))

        for range in allranges:
            oOutput.Line(range)
    else:
        for asn, ranges in dASNs.items():
            oOutput.Line('%s: %s' % (asn, ' '.join(ranges)))

def ASO2CIDR(args, oOutput, options):

    if ISASNFileMissing():
        return
    oCSVReader = csv.reader(open(FileAppDirectory(ASNFILE), 'r', encoding='utf8'))

    dASOs = {}
    for row in oCSVReader:
        ASO = row[2]
        for arg in args:
            if arg.lower() in ASO.lower():
                if not ASO in dASOs:
                    dASOs[ASO] = []
                if options.extra:
                    dASOs[ASO].append('%s\t%s' % (row[0], row[2]))
                else:
                    dASOs[ASO].append(row[0])
    if options.quiet:
        allranges = []

        for asn, ranges in dASOs.items():
            allranges.extend(ranges)

        if options.uniques:
            allranges = list(set(allranges))

        for range in allranges:
            oOutput.Line(range)
    else:
        for asn, ranges in dASOs.items():
            oOutput.Line('%s: %s' % (asn, ' '.join(ranges)))

def CIDR2IP(args, oOutput, options):
    addresses = []

    for arg in args:
        for addr in ipaddress.IPv4Network(arg):
            addresses.append(str(addr))

    if options.uniques:
        addresses = list(set(addresses))

    if options.sort:
        addresses = sorted(addresses, key=lambda x: [int(n) for n in x.split('.')])

    for address in addresses:
        oOutput.Line(address)

def IPINCIDR(args, oOutput, options):
    addresses = []
    dNetworks = {}

    for arg in args:
        with open(arg, 'r') as fIn:
            for line in fIn:
                line = line.rstrip('\n')
                if '/' in line:
                    if '\t' in line:
                        dNetworks[ipaddress.ip_network(line.split('\t')[0])] = line.split('\t')[1]
                    else:
                        dNetworks[ipaddress.ip_network(line)] = None
                else:
                    addresses.append(ipaddress.ip_address(line))

    for network, ASO in dNetworks.items():
        for address in addresses:
            if (address in network) ^ options.invert:
                oOutput.Line('\t'.join([str(address), str(network), ASO]))

def ProcessArguments(command, args, options):
    oOutput = InstantiateCOutput(options)
    
    if command == COMMAND_CIDR2IP:
        CIDR2IP(args, oOutput, options)
    elif command == COMMAND_ASN2CIDR:
        ASN2CIDR(args, oOutput, options)
    elif command == COMMAND_IPINCIDR:
        IPINCIDR(args, oOutput, options)
    elif command == COMMAND_ASO2CIDR:
        ASO2CIDR(args, oOutput, options)

    oOutput.Close()

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] command ...\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-u', '--uniques', action='store_true', default=False, help='Remove duplicates')
    oParser.add_option('-s', '--sort', action='store_true', default=False, help='Sort')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='Quiet')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-v', '--invert', action='store_true', default=False, help='Invert selection')
    oParser.add_option('-e', '--extra', action='store_true', default=False, help='Include extra info')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) < 1:
        oParser.print_help()
        return

    command = args[0]
    if not command in COMMANDS:
        print('Unknown command: %s' % command)
        print('Valid commands: %s' % ', '.join(COMMANDS))
        return

    arguments = args[1:]
    
    if len(arguments) == 0:
        for line in sys.stdin:
            arguments.append(line.rstrip('\n\r'))

    ProcessArguments(command, arguments, options)

if __name__ == '__main__':
    Main()
