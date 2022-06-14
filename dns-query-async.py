#!/usr/bin/env python

__description__ = "Program to perform asynchronous DNS queries"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2022/06/14'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/11/28: start
  2020/12/04: refactoring
  2022/02/06: added getaddr
  2022/02/08: added option -t
  2022/04/23: refactoring, added option -o
  2022/06/14: added man page

Todo:
  implement code for DNS query
  "Timeout while contacting DNS servers"
"""

import optparse
import asyncio
import aiodns
import time
import sys
import pycares
import socket
import textwrap
import os

def PrintManual():
    manual = r'''
Manual:

This tool performs asynchronous DNS queries. By default, it will perform 10000 queries simultaneously.

The first argument is a command. There are 2 commands for the moment: gethost and getaddr
The second argument is a filename: a text file containing the items to resolve.

Use command getaddr to lookup the IP address of the hostnames provided in the input file.
Example:
 dns-query-async.py getaddr names.txt
Result:
 didierstevens.com,1,96.126.103.196
 didierstevenslabs.com,1,96.126.103.196
 Duration: 0.20s

Use command gethost to lookup the hostnames of the IP addresses provided in the input file.
Example:
 dns-query-async.py gethost ips.txt

Use option -s to provide the name servers to use (comma separated list).

Use option -n to change the number of asyncio workers (10000 default).

Use option -t to transform the input list and perform lookups.
For example, take list of subdomains/hostnames https://github.com/m0nad/DNS-Discovery/blob/master/wordlist.wl
Issue the following command:
 dns-query-async.py -t %%.example.com getaddr wordlist.wl
Result:
 0.example.com,0,Domain name not found
 009b.example.com,0,Domain name not found
 01.example.com,0,Domain name not found
 02.example.com,0,Domain name not found
 03.example.com,0,Domain name not found
 1.example.com,0,Domain name not found
 10.example.com,0,Domain name not found
 101a.example.com,0,Domain name not found

The %% in %%.example.com is replaced by each hostname/subdomain in wordlist.wl and then resolved.

Use option -o to write the output to a file.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return list(map(lambda line:line.rstrip('\n'), f.readlines()))
    except:
        return None
    finally:
        if f != sys.stdin:
            f.close()

async def query(name, query_type):
    global resolver

    try:
        result = await resolver.query(name, query_type)
    except aiodns.error.DNSError as e:
        result = e
    return result

async def GethostbyaddrAsync(oResolver, address):
    try:
        result = await oResolver.gethostbyaddr(address)
    except aiodns.error.DNSError as e:
        result = e
    return [address, result]

async def GethostbynameAsync(oResolver, name):
    try:
        result = await oResolver.gethostbyname(name, socket.AF_INET)
    except aiodns.error.DNSError as e:
        result = e
    return [name, result]

def ParseOptionNameservers(nameservers):
    result = nameservers.split(',')
    if result == ['']:
        return None
    return result

def GetHostByAddress(filename, oOutput, options):
    ipv4s = File2Strings(filename)
    if ipv4s == None:
        print('Error reading file %s' % filename)
        return

    loop = asyncio.get_event_loop()
    oResolver = aiodns.DNSResolver(loop=loop, nameservers=ParseOptionNameservers(options.nameservers))

    while len(ipv4s) > 0:
        queue = asyncio.gather(*(GethostbyaddrAsync(oResolver, ipv4) for ipv4 in ipv4s[:options.number]))
        result = loop.run_until_complete(queue)
        for resolve in result:
            if isinstance(resolve[1], pycares.ares_host_result):
                oOutput.Line('%s,1,%s' % (resolve[0], resolve[1].name))
            elif isinstance(resolve[1], aiodns.error.DNSError):
                oOutput.Line('%s,0,%s' % (resolve[0], resolve[1].args[1]))
            else:
                print(resolve)
                raise Exception('Unknown')
        ipv4s = ipv4s[options.number:]

def GetHostByName(filename, oOutput, options):
    hostnames = File2Strings(filename)
    if hostnames == None:
        print('Error reading file %s' % filename)
        return

    if options.transform != '':
        hostnames = [options.transform.replace('%%', hostname) for hostname in hostnames]

    loop = asyncio.get_event_loop()
    oResolver = aiodns.DNSResolver(loop=loop, nameservers=ParseOptionNameservers(options.nameservers))

    while len(hostnames) > 0:
        queue = asyncio.gather(*(GethostbynameAsync(oResolver, ipv4) for ipv4 in hostnames[:options.number]))
        result = loop.run_until_complete(queue)
        for resolve in result:
            if isinstance(resolve[1], pycares.ares_host_result):
                oOutput.Line('%s,1,%s' % (resolve[0], ';'.join(resolve[1].addresses)))
            elif isinstance(resolve[1], aiodns.error.DNSError):
                oOutput.Line('%s,0,%s' % (resolve[0], resolve[1].args[1]))
            else:
                print(resolve)
                raise Exception('Unknown')
        hostnames = hostnames[options.number:]

def CheckArgumentsAndOptions(oParser, args, options, acceptedCommands):
    if options.man:
        oParser.print_help()
        PrintManual()
        return True

    if len(args) != 2:
        oParser.print_help()
        return True

    command = args[0]
    if not command in acceptedCommands:
        print('unknown command: %s' % command)
        print('accepted commands: %s' % ','.join(acceptedCommands))
        return True

    return False

def ParseOptionEncodingSub2(encoding):
    if encoding == '':
        encodingvalue = 'utf8'
        errorsvalue = 'surrogateescape'
    elif ':' in encoding:
        encodingvalue, errorsvalue = encoding.split(':', 1)
    else:
        encodingvalue = encoding
        errorsvalue = None
    return encodingvalue, errorsvalue

def ParseOptionEncodingSub(entry):
    if not entry.startswith('i=') and not entry.startswith('o='):
        entry = 'i=' + entry
    stream, encoding = entry.split('=', 1)
    encodingvalue, errorsvalue = ParseOptionEncodingSub2(encoding)
    return stream, encodingvalue, errorsvalue

def ParseOptionEncoding(streamId, encoding):
    dStreamsPresent = {'i': False, 'o': False}
    dStreams = {'i': ['utf8', 'surrogateescape'], 'o': ['utf8', 'surrogateescape']}
    if encoding != '':
        for entry in encoding.split(','):
            stream, encodingvalue, errorsvalue = ParseOptionEncodingSub(entry)
            if dStreamsPresent[stream]:
                raise Exception('Encoding option error: %s' % encoding)
            else:
                dStreamsPresent[stream] = True
                dStreams[stream] = [encodingvalue, errorsvalue]
    return dStreams[streamId]

class cOutput():
    def __init__(self, filenameOption=None, encoding=''):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.encoding = encoding
        self.encodingvalue, self.errorsvalue = ParseOptionEncoding('o', self.encoding)
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    if sys.version_info[0] > 2:
                        self.fOut = open(self.filename, 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
                    else:
                        self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                if sys.version_info[0] > 2:
                    self.fOut = open(self.filenameOption, 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
                else:
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
            if sys.version_info[0] > 2:
                self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w', encoding=self.encodingvalue, errors=self.errorsvalue)
            else:
                self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

def Main():
    acceptedCommands = ['gethost', 'getaddr']
    moredesc = '''

accepted commands: %s

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com''' % ','.join(acceptedCommands)

    oParser = optparse.OptionParser(usage='usage: %prog [options] command file\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-s', '--nameservers', type=str, default='', help='List of nameservers (,-separated)')
    oParser.add_option('-n', '--number', type=int, default=10000, help='Number of simultaneous requests (default 10000)')
    oParser.add_option('-t', '--transform', type=str, default='', help='Transform input (%%)')
    (options, args) = oParser.parse_args()

    if CheckArgumentsAndOptions(oParser, args, options, acceptedCommands):
        return

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    oOutput = InstantiateCOutput(options)

    start = time.time()

    command = args[0]
    if command == acceptedCommands[0]:
        GetHostByAddress(args[1], oOutput, options)
    elif command == acceptedCommands[1]:
        GetHostByName(args[1], oOutput, options)

    print('Duration: %.2fs' % (time.time() - start))

if __name__ == '__main__':
    Main()
