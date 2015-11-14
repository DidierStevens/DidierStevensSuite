#!/usr/bin/env python

__description__ = 'Find if a file is present in another file'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2015/11/14'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/07/24: start
  2013/07/25: continue
  2013/09/28: bug fixes; added option overlap
  2013/10/17: v0.0.2 added batch mode: processing of several containing files
  2013/10/31: v0.0.3 added error handling ProcessAt
  2014/05/03: v0.0.4 added option skip
  2014/06/11: added options partial, output, range, hexdump
  2014/06/13: added option quiet
  2014/11/25: changed help string for options; added manual
  2015/09/17: 0.0.5 added indicator (End of containing file)
  2015/11/14: bugfix File2StringZIP and added option -r

Todo:
  cOutput: close on dispose
"""

import optparse
import operator
import glob
import collections
import zipfile
import sys
import binascii
import textwrap

MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

find-file-in-file is a program to test if one file (the contained file) can be found inside another file (the containing file).

Here is an example.
We have a file called contained-1.txt with the following content: ABCDEFGHIJKLMNOPQRSTUVWXYZ
and have a file called containing-1.txt with the following content: 0000ABCDEFGHIJKLM1111NOPQRSTUVWXYZ2222

When we execute the following command:
find-file-in-file.py contained-1.txt containing-1.txt

We get this output:
0x00000004 0x0000000d (50%)
0x00000015 0x0000000d (50%)
Finished

This means that the file contained-1.txt was completely found inside file containing-1.txt At position 0x00000004 we found a first part (0x0000000d bytes) and at position 0x00000015 we found a second part (0x0000000d bytes).

We can use option hexdump (-x) to see which bytes were found:
find-file-in-file.py -x contained-1.txt containing-1.txt
0x00000004 0x0000000d (50%)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
0x00000015 0x0000000d (50%)
 4e 4f 50 51 52 53 54 55 56 57 58 59 5a
Finished

The containing file may contain the contained file in an arbitrary order, like file containing-2.txt:
0000NOPQRSTUVWXYZ1111ABCDEFGHIJKLM2222

Example:
find-file-in-file.py -x contained-1.txt containing-2.txt
0x00000015 0x0000000d (50%)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
0x00000004 0x0000000d (50%)
 4e 4f 50 51 52 53 54 55 56 57 58 59 5a
Finished

If a part of the contained file is found at the end of the containing file then indicator (End of containing file) is used, like file containing-4.txt:
0000NOPQRSTUVWXYZ1111ABCDEFGHIJKLM

Example:
find-file-in-file.py -x contained-1.txt containing-4.txt
0x00000015 0x0000000d (50%) (End of containing file)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
0x00000004 0x0000000d (50%)
 4e 4f 50 51 52 53 54 55 56 57 58 59 5a
Finished

The containing file does not need to contain the complete contained file, like file containing-3.txt:
0000ABCDEFGHIJKLM1111

Example:
find-file-in-file.py -x contained-1.txt containing-3.txt
0x00000004 0x0000000d (50%)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
Remaining 13 (50%)

The message "Remaining 13 (50%)" means that the last 13 bytes of the contained file were not found in the containing file (that's 50% of the contained file).

If the contained file starts with a byte sequence not present in the containing file, nothing will be found. Example with file contained-2.txt:
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ

Nothing is found:
find-file-in-file.py -x contained-2.txt containing-1.txt
Remaining 36 (100%)

If you know how long that initial byte sequence is, you can skip it. Use option rangebegin (-b) to specify the position in the contained file from where you want to start searching.
Example:

find-file-in-file.py -x -b 10 contained-2.txt containing-1.txt
0x00000004 0x0000000d (50%)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
0x00000015 0x0000000d (50%)
 4e 4f 50 51 52 53 54 55 56 57 58 59 5a
Finished

If you want to skip bytes at the end of the contained file, use option rangeend (-e).

If you don't know how long that initial byte sequence is, you can instruct find-file-in-file to "brute-force" it. With option partial (-p), one byte at a time will be removed from the beginning of the contained file until a match is found.
Example:

find-file-in-file.py -x -p contained-2.txt containing-1.txt
File: containing-1.txt (partial 0x0a)
0x00000004 0x0000000d (50%)
 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
0x00000015 0x0000000d (50%)
 4e 4f 50 51 52 53 54 55 56 57 58 59 5a
Finished

"(partial 0x0a)" tells you that the first 10 bytes of the contained file were skipped before a match was found.

There are some other options:
-m minimum: find-file-in-file will search for byte sequences of 10 bytes long minimum. If you want to change this minimum, use option -m minimum.
-o overlap: find-file-in-file will not let byte sequences overlap. Use option -o overlap to remove this restriction.
-v verbose: be verbose in batch mode (more than one containing file).
-O output: besides writing output to stdout, write the output also to the given file.
-q quiet: do not output to stdout.

If the contained and/or containing files are ZIP files containing a single file, then the single file is extracted from the ZIP files and analyzed. To analyze the ZIP file and not the file inside the ZIP file, use option -r: regular; consider the ZIP file as a regular file.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def File2StringZIP(filename, regular=False):
    f = None
    oZipfile = None
    if not regular and filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        if len(oZipfile.infolist()) == 1:
            f = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        else:
            f = None
            oZipfile.close()
            oZipfile = None
    if f == None:
        try:
            f = open(filename, 'rb')
        except:
            return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()
        if oZipfile != None:
            oZipfile.close()

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

class cOutput():
    def __init__(self, filename, quiet=False):
        self.filename = filename
        self.quiet = quiet
        if filename == '':
            self.fOut = None
        else:
            self.fOut = open(self.filename, 'w')

    def __del__(self):
        self.Close()

    def Close(self):
        if self.fOut != None:
            self.fOut.close()

    def Print(self, line):
        if not self.quiet:
            print(line)
        if self.fOut != None:
            self.fOut.write(line + '\n')

def Hexdumpline(bytes):
    line = binascii.hexlify(bytes[0:16])
    return ' '.join(line[iIter:iIter + 2] for iIter in range(0, len(line), 2))

def Hexdump(bytes, length, oOutput):
    while length >= 16:
        oOutput.Print(' ' + Hexdumpline(bytes[0:16]))
        length -= 16
        bytes = bytes[16:]
    if length > 0:
        oOutput.Print(' ' + Hexdumpline(bytes[0:length]))

def Match(contained, containing, index, dFound):
    for i in range(len(contained)):
        if i + index >= len(containing) or contained[i] != containing[i + index] or i + index in dFound:
            return i
    return len(contained)

def ScanSub(contained, containing, dFound, options):
    dMatches = {}
    index = 0
    while True:
        result = containing.find(contained[0:options.minimum], index)
        if result == -1:
            break
        found = Match(contained, containing, result, dFound)
        if found > 0:
            dMatches[result] = found
        index = result + 1
    if dMatches == {}:
        return None, None
    return max(dMatches.iteritems(), key=operator.itemgetter(1))

def Scan(fileContaining, contained, containing, singleMode, partial, options):
    global oOutput

    totalLength = 0
    dFound = {}
    remaining = contained
    printFilename = not singleMode
    if options.verbose:
        oOutput.Print('File: %s' % fileContaining)
    while True:
        index, length = ScanSub(remaining, containing, dFound, options)
        if index == None:
            if singleMode or options.verbose:
                oOutput.Print('Remaining %d (%d%%)' % (len(remaining), len(remaining) * 100.0 / len(contained)))
            break
        totalLength += length
        if printFilename and not options.verbose:
            oOutput.Print('File: %s%s' % (fileContaining, IFF(partial != 0, ' (partial 0x%02x)' % partial, '')))
            printFilename = False
        if len(containing[index + length:]) == 0:
            eofMessage = ' (End of containing file)'
        else:
            eofMessage = ''
        oOutput.Print('0x%08x 0x%08x (%d%%)%s' % (index, length, length * 100.0 / len(contained), eofMessage))
        if options.hexdump:
            Hexdump(remaining, length, oOutput)
        if not options.overlap:
            for counter in range(length):
                dFound[counter + index] = True
        remaining = remaining[length:]
        if len(remaining) == 0:
            oOutput.Print('Finished')
            break
        if len(remaining) < options.minimum:
            oOutput.Print('Remaining bytes (%d) smaller than the minimum (option -m)' % len(remaining))
            break
    return totalLength

def FindFileInFile(fileContained, filesContaining, options):
    global oOutput
    oOutput = cOutput(options.output)

    if options.minimum < 1:
        oOutput.Print('Option m is too small')
        return
    containedAll = File2StringZIP(fileContained, options.regular)
    if containedAll == None:
        oOutput.Print('Error reading file %s' % fileContained)
        return
    try:
        filesContaining = ExpandFilenameArguments(filesContaining)
    except Exception as e:
        oOutput.Print(e)
        return
    singleMode = len(filesContaining) == 1

    rangebegin = IFF(options.rangebegin > 0, options.rangebegin, 0)
    rangeend = IFF(options.rangeend > 0, options.rangeend, len(containedAll))
    containedRange = containedAll[rangebegin:rangeend]

    for fileContaining in filesContaining:
        containing = File2StringZIP(fileContaining, options.regular)
        if containing == None:
            if singleMode or options.verbose:
                oOutput.Print('Error reading file %s' % fileContaining)
            continue
        if len(containing) < options.minimum:
            if singleMode or options.verbose:
                oOutput.Print('Error file %s is smaller than the minimum (option -m)' % containing)
            continue

        if options.partial:
            partials = range(len(containedRange) - options.minimum)
            singleMode = False
        else:
            partials = [0]
        while len(partials) > 0:
            contained = containedRange[partials[0]:]
            if len(contained) < options.minimum:
                oOutput.Print('Error file %s is smaller than the minimum (option -m)' % fileContained)
                return
            totalLength = Scan(fileContaining, contained, containing, singleMode, partials[0], options)
            if totalLength > 0:
                partials = partials[totalLength:]
            else:
                partials = partials[1:]

def Main():
    moredesc = '''

Arguments:
file-containing can be a single file, several files, and/or @file
@file: run the command on each file listed in the text file specified
wildcards are supported
batch mode is enabled when more than one file is specified

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] file-contained file-containing [...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-m', '--minimum', type=int, default=10, help='Minimum length of byte-sequence to find (default 10)')
    oParser.add_option('-o', '--overlap', action='store_true', default=False, help='Found sequences may overlap')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='Be verbose in batch mode')
    oParser.add_option('-p', '--partial', action='store_true', default=False, help='Perform partial search of contained file')
    oParser.add_option('-O', '--output', default='', help='Output to file')
    oParser.add_option('-b', '--rangebegin', type=int, default=-1, help='Select the beginning of the contained file (by default byte 0)')
    oParser.add_option('-e', '--rangeend', type=int, default=-1, help='Select the end of the contained file (by default last byte)')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='Hexdump of found bytes')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='Do not output to standard output')
    oParser.add_option('-r', '--regular', action='store_true', default=False, help='Handle a ZIP file like a regular (non-ZIP) file')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) < 2:
        oParser.print_help()
        return
    else:
        FindFileInFile(args[0], args[1:], options)

if __name__ == '__main__':
    Main()
