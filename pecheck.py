#!/usr/bin/env python

__description__ = 'Tool for displaying PE file info'
__author__ = 'Didier Stevens'
__version__ = '0.5.1'
__date__ = '2016/05/24'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

requires pefile http://code.google.com/p/pefile/

History:
  2008/08/10: start
  2012/04/22: V0.2.0 added scan option
  2012/04/26: added CSVLogger and GetVersionInfo
  2013/04/16: V0.3.0 added support for password protected ZIP file
  2014/01/18: V0.4.0 added stdin support
  2014/11/09: added default userdb.txt support
  2014/11/16: added entry point info
  2014/11/18: fixed bug entry point info
  2016/05/16: V0.5.0 added YARA support
  2016/05/17: added GetArgumentsUpdatedWithEnvironmentVariable
  2016/05/21: added overlay info
  2016/05/22: V0.5.1 extended overlay info
  2016/05/23: continued extended overlay info
  2016/05/24: fixed bug GetPEObject

Todo:
"""

import optparse
import os.path
import hashlib
import sys
import time
import zipfile
import signal
import binascii
import shlex
import os

try:
    import pefile
    import peutils
except:
    print('Missing pefile and/or peutils Python module, please check if it is installed.')
    exit()

try:
    import yara
except:
    pass

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

class CSVLogger():
    def __init__(self, prefix, headers, separator=';'):
        self.separator = separator
        self.filename = '%s-%s.csv' % (prefix, Timestamp())
        self.f = open(self.filename, 'w')
        self.f.write(self.separator.join(headers) + '\n')
        self.f.close()

    def PrintAndLog(self, formats, parameters):
        line = self.separator.join(formats) % parameters
        print(line)
        f = open(self.filename, 'a')
        f.write(line + '\n')
        f.close()

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def GetPEObject(filename):
    if filename.lower().endswith('.zip'):
        try:
            oZipfile = zipfile.ZipFile(filename, 'r')
            file = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3('infected'))
        except:
            print('Error opening file %s' % filename)
            print(sys.exc_info()[1])
            sys.exit()
        oPE = pefile.PE(data=file.read())
        file.close()
        oZipfile.close()
    elif filename == '':
        if sys.platform == "win32":
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        oPE = pefile.PE(data=sys.stdin.read())
    else:
        oPE = pefile.PE(filename)
    return oPE

def YARACompile(fileordirname):
    dFilepaths = {}
    if os.path.isdir(fileordirname):
        for root, dirs, files in os.walk(fileordirname):
            for file in files:
                filename = os.path.join(root, file)
                dFilepaths[filename] = filename
    else:
        for filename in ProcessAt(fileordirname):
            dFilepaths[filename] = filename
    return yara.compile(filepaths=dFilepaths)

def NumberOfBytesHumanRepresentation(value):
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

def SingleFile(filename, signatures, options):
    pe = GetPEObject(filename)
    raw = pe.write()
    print("PE check for '%s':" % filename)
    print('Entropy: %f (Min=0.0, Max=8.0)' % pe.sections[0].entropy_H(raw))
    print('MD5     hash: %s' % hashlib.md5(raw).hexdigest())
    print('SHA-1   hash: %s' % hashlib.sha1(raw).hexdigest())
    print('SHA-256 hash: %s' % hashlib.sha256(raw).hexdigest())
    print('SHA-512 hash: %s' % hashlib.sha512(raw).hexdigest())
    for section in pe.sections:
        print('%s entropy: %f (Min=0.0, Max=8.0)' % (''.join(filter(lambda c:c != '\0', str(section.Name))), section.get_entropy()))
    print('Dump Info:')
    print(pe.dump_info())
    print('PEiD:')
    if signatures == None:
        print('Error: signature database missing')
    else:
        print(signatures.match(pe, ep_only = True))

    print('Entry point:')
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
    print 'ep:          0x%08x' % ep
    print 'ep address:  0x%08x' % ep_ava
    for section in pe.sections:
        if section.VirtualAddress <= ep and section.VirtualAddress + section.SizeOfRawData >= ep:
            print 'Section:     %s' % ''.join(filter(lambda c:c != '\0', str(section.Name)))
            print 'ep offset:   0x%08x' % (section.PointerToRawData + ep - section.VirtualAddress)

    print('')
    print('Overlay:')
    overlayOffset = pe.get_overlay_data_start_offset()
    if overlayOffset == None:
        print(' No overlay')
    else:
        print(' Start offset: 0x%08x' % overlayOffset)
        overlaySize = len(raw[overlayOffset:])
        print(' Size:         0x%08x %s %.2f%%' %     (overlaySize, NumberOfBytesHumanRepresentation(overlaySize), float(overlaySize) / float(len(raw)) * 100.0))
        print(' MD5:          %s' % hashlib.md5(raw[overlayOffset:]).hexdigest())
        print(' SHA-256:      %s' % hashlib.sha256(raw[overlayOffset:]).hexdigest())
        overlayMagic = raw[overlayOffset:][:4]
        if type(overlayMagic[0]) == int:
            overlayMagic = ''.join([chr(b) for b in overlayMagic])
        print(' MAGIC:        %s %s' % (binascii.b2a_hex(overlayMagic), ''.join([IFF(ord(b) >= 32, b, '.') for b in overlayMagic])))
        print(' PE file without overlay:')
        print('  MD5:          %s' % hashlib.md5(raw[:overlayOffset]).hexdigest())
        print('  SHA-256:      %s' % hashlib.sha256(raw[:overlayOffset]).hexdigest())

    if options.yara != None:
        print('')
        print('YARA:')
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules = YARACompile(options.yara)
        for result in rules.match(data=str(raw)):
            print(' Rule: %s' % result.rule)
            if options.yarastrings:
                for stringdata in result.strings:
                    print('  %06x %s:' % (stringdata[0], stringdata[1]))
                    print('   %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                    print('   %s' % repr(stringdata[2]))

def FileContentsStartsWithMZ(filename):
    try:
        f = open(filename, 'rb')
    except:
        return False
    try:
        start = f.read(2)
    except:
        return False
    finally:
        f.close()
    return start == 'MZ'

def GetVersionInfo(oPE):
    info = {}
    try:
        oFileInfo = oPE.FileInfo
    except:
        return info
    for oFileInfoEntry in oFileInfo:
        try:
            for oStringTableEntry in oFileInfoEntry.StringTable:
                for key, value in oStringTableEntry.entries.items():
                    info[key] = value
        except:
            pass
    return info

def RVOES(dict, key): # Return Value Or Empty String
    if key in dict:
        return dict[key]
    else:
        return ''

def ScanFile(filename, signatures, minimumEntropy):
    global oLogger

    if not FileContentsStartsWithMZ(filename):
        return
    try:
        pe = GetPEObject(filename)
    except pefile.PEFormatError:
        oLogger.PrintAndLog(('%s', '%s'), (filename, 'PEFormatError'))
        return
    except TypeError:
        oLogger.PrintAndLog(('%s', '%s'), (filename, 'TypeError'))
        return
    try:
        raw = pe.write()
    except MemoryError:
        oLogger.PrintAndLog(('%s', '%s'), (filename, 'MemoryError'))
        return
    entropy = pe.sections[0].entropy_H(raw)
    if entropy >= minimumEntropy:
        countFlagsExecute = 0
        countFlagsExecuteAndWrite = 0
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                countFlagsExecute += 1
            if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_MEM_WRITE:
                countFlagsExecuteAndWrite += 1
        calculatedCRC = pe.generate_checksum()
        crcDifferent = pe.OPTIONAL_HEADER.CheckSum != 0 and pe.OPTIONAL_HEADER.CheckSum != calculatedCRC
        info = GetVersionInfo(pe)
        oLogger.PrintAndLog(('%s', '%f', '%d', '%d', '%d', '%d', '%08X', '%08X', '%d', '%s', '%s', '%s', '%s'), (filename, entropy, len(pe.sections), countFlagsExecute, countFlagsExecuteAndWrite, pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size, pe.OPTIONAL_HEADER.CheckSum, calculatedCRC, crcDifferent, time.asctime(time.gmtime(pe.FILE_HEADER.TimeDateStamp)), repr(RVOES(info, 'CompanyName')), repr(RVOES(info, 'ProductName')), hashlib.md5(raw).hexdigest()))

def ScanFiles(directory, signatures, minimumEntropy):
    try:
        if os.path.isdir(directory):
            for entry in os.listdir(directory):
                ScanFiles(os.path.join(directory, entry), signatures, minimumEntropy)
        else:
            ScanFile(directory, signatures, minimumEntropy)
    except WindowsError:
        if sys.exc_value.winerror == 5:
            pass
        else:
            print(sys.exc_value)
            exit()

def GetArgumentsUpdatedWithEnvironmentVariable(varname):
    envVar = os.getenv(varname)
    if envVar == None:
        return sys.argv[1:]
    else:
        return shlex.split(envVar, posix=False) + sys.argv[1:]

def Main():
    global oLogger

    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file/directory]\nEnvironment variable for options: PECHECK_OPTIONS\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--db', default='', help='the PeID user db file, default userdb.txt in same directory as pecheck')
    oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan folder')
    oParser.add_option('-e', '--entropy', type=float, default=7.0, help='the minimum entropy value for a file to be listed in scan mode (default 7.0)')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file or directory to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    (options, args) = oParser.parse_args(GetArgumentsUpdatedWithEnvironmentVariable('PECHECK_OPTIONS'))

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return

    else:
        try:
            dbfile = options.db
            if dbfile == '':
                dbfile = os.path.join(os.path.dirname(sys.argv[0]), 'userdb.txt')
            signatures = peutils.SignatureDatabase(dbfile)
        except:
            signatures = None
        if len(args) == 0:
            SingleFile('', signatures, options)
        elif options.scan:
            oLogger = CSVLogger('pecheck', ('Filename', 'Entropy', 'Sections', 'Executable sections', 'Executable and writable sections', 'Size AuthentiCode', 'Stored CRC', 'Calculated CRC', 'CRC anomaly', 'Compile date', 'CompanyName', 'ProductName', 'MD5'))
            ScanFiles(args[0], signatures, options.entropy)
        else:
            SingleFile(args[0], signatures, options)

if __name__ == '__main__':
    Main()
