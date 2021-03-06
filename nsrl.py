#!/usr/bin/env python

__description__ = 'NSRL tool'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2021/03/04'

"""

https://DidierStevens.com
Use at your own risk

History:
  2014/01/08: start
  2014/01/30: added option -o
  2015/08/16: added .zip file support
  2015/08/29: continue
  2015/08/31: added man
  2015/09/02: 0.0.2 added ApplicationType
  2015/09/03: added FindNSRLFile
  2021/03/04: 0.0.3 Python 3 and ZIP file layout change

Todo:
"""

import optparse
import csv
import os
import sys
import time
import gzip
import zipfile
import textwrap
import io

def PrintManual():
    manual = '''
Manual:

nsrl.py looks up a list of hashes in the NSRL database and reports the results as a CSV file.

The program takes as input a list of hashes (a text file). By default, the hash used for lookup in the NSRL database is MD5. You can use option -H to select hash algorithm sha-1 or crc32. The list of hashes is read into memory, and then the NSRL database is read and compared with the list of hashes. If there is a match, a line is added to the CSV report for this hash. The list of hashes is deduplicated before matching occurs. So if a hash appears more than once in the list of hashes, it is only matched once. If a hash has more than one entry in the NSRL database, then only the first occurrence will be reported. Unless option -a is used to report all matching entries of the same hash. The first part of the CSV report contains all matching hashes, and the second part all non-matching hashes (hashes that were not found in the NSRL database). Use option -f to report only matching hashes, and option -n to report only non-matching hashes.

The CSV file is outputted to console and written to a CSV file with the same name has the list of hashes, but with a timestamp appended. To prevent output to the console, use option -q. T choose the output filename, use option -o. The separator used in the CSV file is ;. This can be changed with option -s.

The second argument given to nsrl.py is the NSRL database. This can be the NSRL database text file (NSRLFile.txt), the gzip compressed NSRL database text file or the ZIP file containing the NSRL database text file. I use the "reduced set" or minimal hashset (each hash appears only once) found on http://www.nsrl.nist.gov/Downloads.htm. The second argument can be omitted if a gzip compressed NSRL database text file NSRLFile.txt.gz is stored in the same directory as nsrl.py.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

class cCSVLogger():
    def __init__(self, prefix, headers, quiet, separator=';', prefixIsFullName=False):
        self.separator = separator
        self.quiet = quiet
        if prefixIsFullName:
            self.filename = prefix
        else:
            self.filename = '%s-%s.csv' % (prefix, Timestamp())
        self.f = open(self.filename, 'w')
        self.f.write(self.separator.join(headers) + '\n')
        self.f.close()

    def PrintAndLog(self, parameters):
        line = self.separator.join(parameters)
        if not self.quiet:
            print(line)
        f = open(self.filename, 'a')
        f.write(line + '\n')
        f.close()

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

def LoadProducts(fIn):
    dProducts = {}
    header = None
    if sys.version_info[0] >= 3:
        reader = csv.reader(io.TextIOWrapper(fIn, encoding='utf8', errors='surrogateescape'), delimiter=',', skipinitialspace=True)
    else:
        reader = csv.reader(fIn, delimiter=',', skipinitialspace=True)
    for row in reader:
        if header == None:
            header = row
        else:
            dProducts[row[0]] = row[6]
    fIn.close()
    return dProducts

def GetFilename(oZipfile, filename):
    for name in oZipfile.namelist():
        if name.lower().endswith(filename.lower()):
            return name
    return None

def HashSub(filenameHashes, filenameNSRL, options):
    dHashes = {}
    dProducts = {}
    for hash1 in File2Strings(filenameHashes):
        dHashes[hash1.strip().lower()] = False
    header = None
    if os.path.splitext(filenameNSRL)[1].lower() == '.zip':
        oZipfile = zipfile.ZipFile(filenameNSRL, 'r')
        fIn = oZipfile.open(GetFilename(oZipfile,'NSRLFile.txt'), 'r')
        filenameProd = GetFilename(oZipfile, 'NSRLProd.txt')
        if filenameProd != None:
            dProducts = LoadProducts(oZipfile.open(filenameProd, 'r'))
        oZipfile.close()
    elif os.path.splitext(filenameNSRL)[1].lower() == '.gz':
        fIn = gzip.GzipFile(filenameNSRL, 'rb')
    else:
        fIn = open(filenameNSRL, 'rb')

    if sys.version_info[0] >= 3:
        reader = csv.reader(io.TextIOWrapper(fIn, encoding='utf8', errors='surrogateescape'), delimiter=',', skipinitialspace=True)
    else:
        reader = csv.reader(fIn, delimiter=',', skipinitialspace=True)
    for row in reader:
        if header == None:
            header = row
            try:
                indexHash = header.index(options.hash.upper())
            except:
                print('Hash %s not found in header:' % options.hash.upper())
                print(header)
                return
            headers = [header[indexHash]] + header[3:] + ['ApplicationType']
            if options.output:
                oCSVLogger = cCSVLogger(options.output, headers, options.quiet, options.separator, True)
            else:
                oCSVLogger = cCSVLogger(os.path.splitext(filenameHashes)[0], headers, options.quiet, options.separator)
        else:
            hash2 = row[indexHash].lower()
            if hash2 in dHashes:
                if not options.notfoundonly:
                    if options.allfinds or not dHashes[hash2]:
                        oCSVLogger.PrintAndLog([hash2] + row[3:] + [dProducts.get(row[5], '')])
                dHashes[hash2] = True
    fIn.close()
    if not options.foundonly:
        for key in sorted(dHashes.keys()):
            if not dHashes[key]:
                oCSVLogger.PrintAndLog([key, '', '', '', '', '', ''])

def FindNSRLFile():
    fileZIP = os.path.join(os.path.dirname(sys.argv[0]), 'rds.zip')
    if os.path.isfile(fileZIP):
        return fileZIP
    fileGZ = os.path.join(os.path.dirname(sys.argv[0]), 'NSRLFile.txt.gz')
    if os.path.isfile(fileGZ):
        return fileGZ
    return os.path.join(os.path.dirname(sys.argv[0]), 'NSRLFile.txt')

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] filemd5 [NSRL-file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--separator', default=';', help='separator to use (default is ;)')
    oParser.add_option('-H', '--hash', default='md5', help='NSRL hash to use, options: SHA-1, MD5, CRC32 (default MD5)')
    oParser.add_option('-f', '--foundonly', action='store_true', default=False, help='only report found hashes')
    oParser.add_option('-n', '--notfoundonly', action='store_true', default=False, help='only report missing hashes')
    oParser.add_option('-a', '--allfinds', action='store_true', default=False, help='report all matching hashes, not just first one')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='do not produce console output')
    oParser.add_option('-o', '--output', default='', help='output to file')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0 or len(args) > 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 2:
        HashSub(args[0], args[1], options)
    else:
        HashSub(args[0], FindNSRLFile(), options)

if __name__ == '__main__':
    Main()
