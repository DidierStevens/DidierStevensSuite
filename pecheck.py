#!/usr/bin/env python

__description__ = 'Tool for displaying PE file info'
__author__ = 'Didier Stevens'
__version__ = '0.6.0'
__date__ = '2016/12/12'

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
  2016/08/02: V0.5.2 added signature analysis if pyasn installed
  2016/12/01: added options -g -D -x -a -S
  2016/12/12: V0.6.0 added option -o

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
import re

dumplinelength = 16
REGEX_STANDARD = '[\x09\x20-\x7E]'

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

def Signature(pe):
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print(' No signature')
        return

    signature = pe.write()[address + 8:address + size]

    try:
        from pyasn1.codec.der import decoder as der_decoder
    except:
        print(' Signature present but error importing pyasn1 module')
        return
    try:
        from pyasn1_modules import rfc2315
    except:
        print(' Signature present but error importing pyasn1_modules module')
        return

    contentInfo, _ = der_decoder.decode(str(signature), asn1Spec=rfc2315.ContentInfo())
    contentType = contentInfo.getComponentByName('contentType')
    contentInfoMap = {
        (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
        (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
        (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
        (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
        (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
        (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
    }
    content, _ = der_decoder.decode(contentInfo.getComponentByName('content'), asn1Spec=contentInfoMap[contentType])

    for line in content.prettyPrint().split('\n'):
        print(line)
        oMatch = re.match('( *)value=0x....(.+)', line)
        if oMatch != None:
            print(oMatch.groups()[0] + '      ' + repr(binascii.a2b_hex(oMatch.groups()[1])))

#    for idx in range(len(content)):
#        print(content.getNameByPosition(idx))
#        print(content.getNameByPosition(idx), content.getComponentByPosition(idx))

def SingleFileInfo(filename, signatures, options):
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

    print('Signature:')
    Signature(pe)
    print('')

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

class cDumpStream():
    def __init__(self):
        self.text = ''

    def Addline(self, line):
        if line != '':
            self.text += line + '\n'

    def Content(self):
        return self.text

def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != '':
            oDumpStream.Addline(hexDump)
            hexDump = ''
        hexDump += IFF(hexDump == '', '', ' ') + '%02X' % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()

def CombineHexAscii(hexDump, asciiDump):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (dumplinelength - len(asciiDump)))) + asciiDump

def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ''
    asciiDump = ''
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != '':
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = '%08X:' % i
            asciiDump = ''
        hexDump+= ' %02X' % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, '.')
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + '{%d,}'
    return re.findall(regex % 4, data)

def ExtractStringsUNICODE(data):
    regex = '((' + REGEX_STANDARD + '\x00){%d,})'
    return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def ExtractStrings(data):
    return ExtractStringsASCII(data) + ExtractStringsUNICODE(data)

def DumpFunctionStrings(data):
    return ''.join([extractedstring + '\n' for extractedstring in ExtractStrings(data)])

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

def ParseGetData(expression):
    terms = expression.split(',')
    if len(terms) != 2:
        return None
    if not terms[0].strip().startswith('0x'):
        return None
    if not terms[1].strip().startswith('0x'):
        return None
    return (int(terms[0].strip()[2:], 16), int(terms[1].strip()[2:], 16))

def GenerateMAGIC(data):
    return binascii.b2a_hex(data) + ' ' + ''.join([IFF(ord(c) >= 32 and ord(c) <= 128, c, '.') for c in data])

def Resources(filename, options):
    counter = 1
    pe = GetPEObject(filename)

    if options.dump:
        DumpFunction = lambda x:x
        IfWIN32SetBinary(sys.stdout)
    elif options.hexdump:
        DumpFunction = HexDump
    elif options.asciidump:
        DumpFunction = HexAsciiDump
    elif options.strings:
        DumpFunction = DumpFunctionStrings
    else:
        DumpFunction = HexAsciiDump

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                column1 = str(resource_type.name)
            else:
                column1 = '[%s]' % pefile.RESOURCE_TYPE.get(resource_type.struct.Id, '-')
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if resource_id.name is not None:
                        column2 = str(resource_id.name)
                    else:
                        column2 = '%d' % resource_id.struct.Id
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            if hasattr(resource_lang, 'data'):
                                column3 = '(%d,%d)' % (resource_lang.data.lang, resource_lang.data.sublang)
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                if options.getdata == '':
                                    print('%4d: %-20s %-20s %s %7d %s' % (counter, column1, column2, column3, resource_lang.data.struct.Size, GenerateMAGIC(data[0:8])))
                                elif int(options.getdata) == counter:
                                    StdoutWriteChunked(DumpFunction(data))
                                counter += 1
                    else:
                        if options.getdata == '':
                            print('%4d: %-20s %-20s' % (counter, column1, column2))
                        counter += 1
            else:
                if options.getdata == '':
                    print('%4d: %-20s' % (counter, column1))
                counter += 1

def SingleFile(filename, signatures, options):
    if options.overview == 'r':
        Resources(filename, options)
    elif options.getdata != '':
        pe = GetPEObject(filename)
        if options.dump:
            DumpFunction = lambda x:x
            IfWIN32SetBinary(sys.stdout)
        elif options.hexdump:
            DumpFunction = HexDump
        elif options.asciidump:
            DumpFunction = HexAsciiDump
        elif options.strings:
            DumpFunction = DumpFunctionStrings
        else:
            DumpFunction = HexAsciiDump
        parsed = ParseGetData(options.getdata)
        if parsed == None:
            print('Error getdata syntax error: %s' % options.getdata)
            return
        StdoutWriteChunked(DumpFunction(pe.get_data(parsed[0], parsed[1])))
    else:
        SingleFileInfo(filename, signatures, options)

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
    oParser.add_option('-g', '--getdata', type=str, default='', help='Get data from the PE file (example 0x1234,0x100)')
    oParser.add_option('-D', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-S', '--strings', action='store_true', default=False, help='perform strings dump')
    oParser.add_option('-o', '--overview', type=str, default='', help='Accepted value: r for overview of resources')
    (options, args) = oParser.parse_args(GetArgumentsUpdatedWithEnvironmentVariable('PECHECK_OPTIONS'))

    if len(args) > 1 or options.overview != '' and options.overview != 'r':
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
