#!/usr/bin/env python

__description__ = 'Tool for displaying PE file info'
__author__ = 'Didier Stevens'
__version__ = '0.7.13'
__date__ = '2021/02/25'

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
  2017/07/02: V0.7.0 added sections (s) to option -o; added # support for option -y
  2017/11/01: V0.7.1 added -g support for -o s; added cDump
  2017/11/03: continued
  2018/02/12: V0.7.2 bug fix Signature()
  2018/05/17: V0.7.3 better error handling for PEiD files
  2018/08/18: V0.7.4 better error handling signatures
  2019/02/26: V0.7.5 added overlay (o) to option -g; added #x# and #r# to option -y; added option -A
  2019/02/26: V0.7.6 fixed exit bug for pyinstaller
  2019/09/13: V0.7.7 added strip (s) to option -g; added option -l
  2019/09/16: continued -l P
  2019/09/17: continue; added option -m
  2019/09/28: V0.7.8 added MD5 hash to -l P report
  2019/10/27: introduced environment variable DSS_DEFAULT_HASH_ALGORITHMS
  2020/01/25: 0.7.9 import zlib; Python 3 fixes;
  2020/01/26: Python 3 fixes;
  2020/03/01: 0.7.10 added ProcessDumpInfo and Fixed_get_overlay_data_start_offset
  2020/03/02: added TLSCallbacks
  2020/07/04: 0.7.11 fixed typo in man page
  2020/07/26: fixes Python 3 bug for overlays reported by Lenny Zeltser; fixed ASCII 128; added option --verbose
  2020/10/22: 0.7.12 extra info (names) with -l P; Python 3 bug
  2021/02/25: 0.7.13 added signature hash

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
import struct
import textwrap
import zlib
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO

dumplinelength = 16
REGEX_STANDARD = '[\x09\x20-\x7E]'

try:
    import pefile
    import peutils
except ImportError:
    print('Missing pefile and/or peutils Python module, please check if it is installed.')
    sys.exit()

try:
    import yara
except:
    pass

def PrintManual():
    manual = '''
Manual:

This manual is a work in progress.

Use option -l to locate and select PE files embedded inside the provided file.
Use -l P to get an overview of all embedded PE files, like this:

C:\Demo>pecheck.py -l P sample.png.vir
1: 0x00002ebb DLL 32-bit 0x00016eba 3bd4fcbee95711392260549669df7236 0x000270ba (EOF)
2: 0x00016ebb DLL 64-bit 0x000270ba 6eede113112f85b0ae99a2210e07cdd0 0x000270ba (EOF)

The first column is the position of the embedded PE file, the fourth column is the end of the embedded PE file without overlay, and the sixth column is the end with overlay.
The fifth column is the hash of the embedded PE file without overlay. By default, it's the MD5 hash, but this can be changed by setting environment variable DSS_DEFAULT_HASH_ALGORITHMS.
Like this: set DSS_DEFAULT_HASH_ALGORITHMS=sha256

After producing an overview of embedded PE files (with option -l P), select an embedded PE file for further analysis, like this:

C:\Demo>pecheck.py -l 2 sample.png.vir

Use option -g o (o = overlay) to extract the overlay, and -g s (s = stripped) to extract the PE file without overlay.

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

#Convert to String If Python 2
def C2SIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return str(data)

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
            f.close()

def File2String(filename):
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

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ReadFile(filename):
    if filename.lower().endswith('.zip'):
        try:
            oZipfile = zipfile.ZipFile(filename, 'r')
            file = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3('infected'))
        except:
            print('Error opening file %s' % filename)
            print(sys.exc_info()[1])
            sys.exit()
        data = file.read()
        file.close()
        oZipfile.close()
    elif filename == '':
        if sys.platform == "win32":
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        if sys.version_info[0] > 2:
            data = sys.stdin.buffer.read()
        else:
            data = sys.stdin.read()
    else:
        data = File2String(filename)
    return data

def YARACompile(ruledata):
    if ruledata.startswith('#'):
        if ruledata.startswith('#h#'):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith('#b#'):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith('#s#'):
            rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#q#'):
            rule = ruledata[3:].replace("'", '"')
        elif ruledata.startswith('#x#'):
            rule = 'rule hexadecimal {strings: $a = { %s } condition: $a}' % ruledata[3:]
        elif ruledata.startswith('#r#'):
            rule = 'rule regex {strings: $a = /%s/ ascii wide nocase condition: $a}' % ruledata[3:]
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule), rule
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths), ','.join(dFilepaths.values())

def NumberOfBytesHumanRepresentation(value):
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

#can be removed if following PR is merged: https://github.com/erocarrera/pefile/pull/254/files
#this is a fix for when a digital signature is present
def Fixed_get_overlay_data_start_offset(oPE):
    overlayOffset = oPE.get_overlay_data_start_offset()
    if overlayOffset == None:
        return overlayOffset

    try:
        security = oPE.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    except IndexError:
        return overlayOffset

    if overlayOffset > security.VirtualAddress + security.Size:
        return overlayOffset

    if len(oPE.__data__) > security.VirtualAddress + security.Size:
        return security.VirtualAddress + security.Size
    else:
        return None

def Signature(pe):
    try:
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    except IndexError:
        print(' No signature')
        return

    address = security.VirtualAddress
    size = security.Size

    if address == 0:
        print(' No signature')
        return

    signature = pe.write()[address + 8:address + size]
    if len(signature) != size - 8:
        print(' Unable to extract full signature, file is most likely truncated')
        print(' Extracted: %d bytes' % len(signature))
        print(' Expected: %d bytes' % (size - 8))
        return

    print(' Signature size: 0x%06x' % len(signature))
    hashvalue, hashalgo = CalculateChosenHash(signature)
    print(' Signature %s hash: %s' % (hashalgo, hashvalue))

    try:
        from pyasn1.codec.der import decoder as der_decoder
    except ImportError:
        print(' Signature present but error importing pyasn1 module')
        return
    try:
        from pyasn1_modules import rfc2315
    except ImportError:
        print(' Signature present but error importing pyasn1_modules module')
        return

    signatureArg = C2SIP2(signature)

    contentInfo, _ = der_decoder.decode(signatureArg, asn1Spec=rfc2315.ContentInfo())
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
            if sys.version_info[0] > 2:
                print(oMatch.groups()[0] + '      ' + repr(binascii.a2b_hex(oMatch.groups()[1]).decode()))
            else:
                print(oMatch.groups()[0] + '      ' + repr(binascii.a2b_hex(oMatch.groups()[1])))

#    for idx in range(len(content)):
#        print(content.getNameByPosition(idx))
#        print(content.getNameByPosition(idx), content.getComponentByPosition(idx))

def TLSCallbacks(oPE):
    if not hasattr(oPE, 'DIRECTORY_ENTRY_TLS'):
        print(' No TLS')
        return

    tlsCallbacksRva = oPE.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - oPE.OPTIONAL_HEADER.ImageBase
    if oPE.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE:
        format = '<Q'
    else:
        format = '<I'
    formatSize = struct.calcsize(format)
    foundSection = None
    for section in oPE.sections:
        if section.contains_rva(tlsCallbacksRva):
            foundSection = section
            tlsCallbacksOffset = section.get_offset_from_rva(tlsCallbacksRva)
            callbacksArray = oPE.__data__[tlsCallbacksOffset:section.PointerToRawData + section.SizeOfRawData]
            callbacks = []
            while len(callbacksArray) >= formatSize:
                callbackVA = struct.unpack(format, callbacksArray[0:formatSize])[0]
                if callbackVA == 0:
                    break
                else:
                    callbacks.append(callbackVA)
                    callbacksArray = callbacksArray[formatSize:]

            print(' Section:     %s' % SectionNameToString(section.Name))
            print(' Number of callbacks: %d' % len(callbacks))
            for callback in callbacks:
                print('   Address:  0x%08x' % callback)
    if foundSection == None:
        print(' AddressOfCallBacks not found in any section: 0x%08x' % oPE.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)

def ProcessDumpInfo(oPE):
    dumpinfo = oPE.dump_info()
    lines = dumpinfo.split('\n')
    result = []
    relocation = False
    for line in lines:
        skipLine = False
        if line == 'Ordinal      RVA         Name':
            result.append(oPE.DIRECTORY_ENTRY_EXPORT.name.decode())
            result.append('')
        if not relocation and line == '[IMAGE_BASE_RELOCATION]':
            relocation = True
        elif relocation and line == '':
            relocation = False
        elif relocation and line.startswith('   '):
            skipLine = True
        if not skipLine:
            result.append(line)
    return '\n'.join(result)
    
def SingleFileInfo(filename, data, signatures, options):
    pe = pefile.PE(data=data)
    raw = pe.write()
    print("PE check for '%s':" % filename)
    print('Entropy: %f (Min=0.0, Max=8.0)' % pe.sections[0].entropy_H(raw))
    print('MD5     hash: %s' % hashlib.md5(raw).hexdigest())
    print('SHA-1   hash: %s' % hashlib.sha1(raw).hexdigest())
    print('SHA-256 hash: %s' % hashlib.sha256(raw).hexdigest())
    print('SHA-512 hash: %s' % hashlib.sha512(raw).hexdigest())
    for section in pe.sections:
        print('%s entropy: %f (Min=0.0, Max=8.0)' % (SectionNameToString(section.Name), section.get_entropy()))

    print('Dump Info:')
    print(ProcessDumpInfo(pe))

    print('Signature:')
    try:
        Signature(pe)
    except Exception as e:
        print(' Error occured: %s' % e)
    print('')

    print('PEiD:')
    if type(signatures) == str:
        print(signatures)
    else:
        print(signatures.match(pe, ep_only = True))

    print('Entry point:')
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
    print('ep:          0x%08x' % ep)
    print('ep address:  0x%08x' % ep_ava)
    for section in pe.sections:
        if section.VirtualAddress <= ep and section.VirtualAddress + section.SizeOfRawData >= ep:
            print('Section:     %s' % SectionNameToString(section.Name))
            print('ep offset:   0x%08x' % (section.PointerToRawData + ep - section.VirtualAddress))

    print('')
    print('TLS Callbacks:')
    try:
        TLSCallbacks(pe)
    except Exception as e:
        print(' Error occured: %s' % e)
    print('')

    print('Overlay:')
    overlayOffset = Fixed_get_overlay_data_start_offset(pe)
    if overlayOffset == None:
        print(' No overlay')
    else:
        print(' Start offset: 0x%08x' % overlayOffset)
        overlaySize = len(raw[overlayOffset:])
        print(' Size:         0x%08x %s %.2f%%' %     (overlaySize, NumberOfBytesHumanRepresentation(overlaySize), float(overlaySize) / float(len(raw)) * 100.0))
        print(' MD5:          %s' % hashlib.md5(raw[overlayOffset:]).hexdigest())
        print(' SHA-256:      %s' % hashlib.sha256(raw[overlayOffset:]).hexdigest())
        print(' MAGIC:        %s' % GenerateMAGIC(raw[overlayOffset:][:4]))
        print(' PE file without overlay:')
        print('  MD5:          %s' % hashlib.md5(raw[:overlayOffset]).hexdigest())
        print('  SHA-256:      %s' % hashlib.sha256(raw[:overlayOffset]).hexdigest())

    if options.yara != None:
        print('')
        print('YARA:')
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)
        for result in rules.match(data=str(raw)):
            print(' Rule: %s' % result.rule)
            if options.yarastrings:
                for stringdata in result.strings:
                    print('  %06x %s:' % (stringdata[0], stringdata[1]))
                    print('   %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                    print('   %s' % repr(stringdata[2]))

class cDump():
    def __init__(self, data, prefix='', offset=0, dumplinelength=16):
        self.data = data
        self.prefix = prefix
        self.offset = offset
        self.dumplinelength = dumplinelength

    def HexDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        for i, b in enumerate(self.data):
            if i % self.dumplinelength == 0 and hexDump != '':
                oDumpStream.Addline(hexDump)
                hexDump = ''
            hexDump += IFF(hexDump == '', '', ' ') + '%02X' % self.C2IIP2(b)
        oDumpStream.Addline(hexDump)
        return oDumpStream.Content()

    def CombineHexAscii(self, hexDump, asciiDump):
        if hexDump == '':
            return ''
        countSpaces = 3 * (self.dumplinelength - len(asciiDump))
        if len(asciiDump) <= self.dumplinelength / 2:
            countSpaces += 1
        return hexDump + '  ' + (' ' * countSpaces) + asciiDump

    def HexAsciiDump(self, rle=False):
        oDumpStream = self.cDumpStream(self.prefix)
        position = ''
        hexDump = ''
        asciiDump = ''
        previousLine = None
        countRLE = 0
        for i, b in enumerate(self.data):
            b = self.C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    line = self.CombineHexAscii(hexDump, asciiDump)
                    if not rle or line != previousLine:
                        if countRLE > 0:
                            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
                        oDumpStream.Addline(position + line)
                        countRLE = 0
                    else:
                        countRLE += 1
                    previousLine = line
                position = '%08X:' % (i + self.offset)
                hexDump = ''
                asciiDump = ''
            if i % self.dumplinelength == self.dumplinelength / 2:
                hexDump += ' '
            hexDump += ' %02X' % b
            asciiDump += IFF(b >= 32 and b < 127, chr(b), '.')
        if countRLE > 0:
            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
        oDumpStream.Addline(self.CombineHexAscii(position + hexDump, asciiDump))
        return oDumpStream.Content()

    def Base64Dump(self, nowhitespace=False):
        encoded = binascii.b2a_base64(self.data)
        if nowhitespace:
            return encoded
        oDumpStream = self.cDumpStream(self.prefix)
        length = 64
        for i in range(0, len(encoded), length):
            oDumpStream.Addline(encoded[0+i:length+i])
        return oDumpStream.Content()

    class cDumpStream():
        def __init__(self, prefix=''):
            self.oStringIO = StringIO()
            self.prefix = prefix

        def Addline(self, line):
            if line != '':
                self.oStringIO.write(self.prefix + line + '\n')

        def Content(self):
            return self.oStringIO.getvalue()

    @staticmethod
    def C2IIP2(data):
        if sys.version_info[0] > 2:
            return data
        else:
            return ord(data)

def HexDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump(rle=rle)

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
    if sys.version_info[0] > 2:
        if isinstance(data, str):
            sys.stdout.write(data)
        else:
            sys.stdout.buffer.write(data)
    else:
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
    return binascii.b2a_hex(data).decode() + ' ' + ''.join([IFF(P23Ord(c) >= 32 and P23Ord(c) < 127, chr(P23Ord(c)), '.') for c in data])

def GetDumpFunction(options):
    if options.dump:
        DumpFunction = lambda x:x
        IfWIN32SetBinary(sys.stdout)
    elif options.hexdump:
        DumpFunction = HexDump
    elif options.asciidump:
        DumpFunction = HexAsciiDump
    elif options.strings:
        DumpFunction = DumpFunctionStrings
    elif options.asciidumprle:
        DumpFunction = lambda x: HexAsciiDump(x, True)
    else:
        DumpFunction = HexAsciiDump
    return DumpFunction

def Resources(data, options):
    counter = 1
    pe = pefile.PE(data=data)
    DumpFunction = GetDumpFunction(options)

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

def SectionNameToString(name):
    if sys.version_info[0] > 2:
        return ''.join([chr(b) for b in name if b != 0])
    else:
        return ''.join(filter(lambda c:c != '\0', str(name)))

def Sections(data, options):
    counter = 1
    pe = pefile.PE(data=data)
    DumpFunction = GetDumpFunction(options)

    #http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    dSections = {
        #The packer/protector/tools section names/keywords
        '.aspack': 'Aspack packer',
        '.adata': 'Aspack packer/Armadillo packer',
        'ASPack': 'Aspack packer',
        '.ASPack': 'ASPAck Protector',
        '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
        '.ccg': 'CCG Packer (Chinese Packer)',
        '.charmve': 'Added by the PIN tool',
        'BitArts': 'Crunch 2.0 Packer',
        'DAStub': 'DAStub Dragon Armor protector',
        '!EPack': 'Epack packer',
        'FSG!': 'FSG packer (not a section name, but a good identifier)',
        '.gentee': 'Gentee installer',
        'kkrunchy': 'kkrunchy Packer',
        '.mackt': 'ImpRec-created section',
        '.MaskPE': 'MaskPE Packer',
        'MEW': 'MEW packer',
        '.MPRESS1': 'Mpress Packer',
        '.MPRESS2': 'Mpress Packer',
        '.neolite': 'Neolite Packer',
        '.neolit': 'Neolite Packer',
        '.nsp1': 'NsPack packer',
        '.nsp0': 'NsPack packer',
        '.nsp2': 'NsPack packer',
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        '.packed': 'RLPack Packer (first section)',
        'pebundle': 'PEBundle Packer',
        'PEBundle': 'PEBundle Packer',
        'PEC2TO': 'PECompact packer',
        'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
        'PEC2': 'PECompact packer',
        'pec1': 'PECompact packer',
        'pec2': 'PECompact packer',
        'PEC2MO': 'PECompact packer',
        'PELOCKnt': 'PELock Protector',
        '.perplex': 'Perplex PE-Protector',
        'PESHiELD': 'PEShield Packer',
        '.petite': 'Petite Packer',
        '.pinclie': 'Added by the PIN tool',
        'ProCrypt': 'ProCrypt Packer',
        '.RLPack': 'RLPack Packer (second section)',
        '.rmnet': 'Ramnit virus marker',
        'RCryptor': 'RPCrypt Packer',
        '.RPCrypt': 'RPCrypt Packer',
        '.seau': 'SeauSFX Packer',
        '.sforce3': 'StarForce Protection',
        '.spack': 'Simple Pack (by bagie)',
        '.svkp': 'SVKP packer',
        'Themida': 'Themida Packer',
        '.Themida': 'Themida Packer',
        '.taz': 'Some version os PESpin',
        '.tsuarch': 'TSULoader',
        '.tsustub': 'TSULoader',
        '.packed': 'Unknown Packer',
        'PEPACK!!': 'Pepack',
        '.Upack': 'Upack packer',
        '.ByDwing': 'Upack Packer',
        'UPX0': 'UPX packer',
        'UPX1': 'UPX packer',
        'UPX2': 'UPX packer',
        'UPX!': 'UPX packer',
        '.UPX0': 'UPX Packer',
        '.UPX1': 'UPX Packer',
        '.UPX2': 'UPX Packer',
        '.vmp0': 'VMProtect packer',
        '.vmp1': 'VMProtect packer',
        '.vmp2': 'VMProtect packer',
        'VProtect': 'Vprotect Packer',
        '.winapi': 'Added by API Override tool',
        'WinLicen': 'WinLicense (Themida) Protector',
        '_winzip_': 'WinZip Self-Extractor',
        '.WWPACK': 'WWPACK Packer',
        '.yP': 'Y0da Protector',
        '.y0da': 'Y0da Protector',

        #List of popular section names
        '.00cfg': 'Control Flow Guard (CFG) section (added by newer versions of Visual Studio)',
        '.arch': 'Alpha-architecture section',
        '.autoload_text': 'cygwin/gcc; the Cygwin DLL uses a section to avoid copying certain data on fork.',
        '.bindat': 'Binary data (also used by one of the downware installers based on LUA)',
        '.bootdat': 'section that can be found inside Visual Studio files; contains palette entries',
        '.bss': 'Uninitialized Data Section',
        '.BSS': 'Uninitialized Data Section',
        '.buildid': 'gcc/cygwin; Contains debug information (if overlaps with debug directory)',
        '.CLR_UEF': '.CLR Unhandled Exception Handler section; see https://github.com/dotnet/coreclr/blob/master/src/vm/excep.h',
        '.code': 'Code Section',
        '.cormeta': '.CLR Metadata Section',
        '.complua': 'Binary data, most likely compiled LUA (also used by one of the downware installers based on LUA)',
        '.CRT': 'Initialized Data Section  (C RunTime)',
        '.cygwin_dll_common': "cygwin section containing flags representing Cygwin's capabilities; refer to cygwin.sc and wincap.cc inside Cygwin run-time",
        '.data': 'Data Section',
        '.DATA': 'Data Section',
        '.data1': 'Data Section',
        '.data2': 'Data Section',
        '.data3': 'Data Section',
        '.debug': 'Debug info Section',
        '.debug$F': 'Debug info Section (Visual C++ version <7.0)',
        '.debug$P': 'Debug info Section (Visual C++ debug information',
        '.debug$S': 'Debug info Section (Visual C++ debug information',
        '.debug$T': 'Debug info Section (Visual C++ debug information',
        '.drectve ': 'directive section (temporary, linker removes it after processing it; should not appear in a final PE image)',
        '.didat': 'Delay Import Section',
        '.didata': 'Delay Import Section',
        '.edata': 'Export Data Section',
        '.eh_fram': 'gcc/cygwin; Exception Handler Frame section',
        '.export': 'Alternative Export Data Section',
        '.fasm': 'FASM flat Section',
        '.flat': 'FASM flat Section',
        '.gfids': 'section added by new Visual Studio (14.0); purpose unknown',
        '.giats': 'section added by new Visual Studio (14.0); purpose unknown',
        '.gljmp': 'section added by new Visual Studio (14.0); purpose unknown',
        '.glue_7t': 'ARMv7 core glue functions (thumb mode)',
        '.glue_7': 'ARMv7 core glue functions (32-bit ARM mode)',
        '.idata': 'Initialized Data Section  (Borland)',
        '.idlsym': 'IDL Attributes (registered SEH)',
        '.impdata': 'Alternative Import data section',
        '.itext': 'Code Section  (Borland)',
        '.ndata': 'Nullsoft Installer section',
        '.orpc': 'Code section inside rpcrt4.dll',
        '.pdata': 'Exception Handling Functions Section (PDATA records)',
        '.rdata': 'Read-only initialized Data Section  (MS and Borland)',
        '.reloc': 'Relocations Section',
        '.rodata': 'Read-only Data Section',
        '.rsrc': 'Resource section',
        '.sbss': 'GP-relative Uninitialized Data Section',
        '.script': 'Section containing script',
        '.shared': 'Shared section',
        '.sdata': 'GP-relative Initialized Data Section',
        '.srdata': 'GP-relative Read-only Data Section',
        '.stab': 'Created by Haskell compiler (GHC)',
        '.stabstr': 'Created by Haskell compiler (GHC)',
        '.sxdata': 'Registered Exception Handlers Section',
        '.text': 'Code Section',
        '.text0': 'Alternative Code Section',
        '.text1': 'Alternative Code Section',
        '.text2': 'Alternative Code Section',
        '.text3': 'Alternative Code Section',
        '.textbss': 'Section used by incremental linking',
        '.tls': 'Thread Local Storage Section',
        '.tls$': 'Thread Local Storage Section',
        '.udata': 'Uninitialized Data Section',
        '.vsdata': 'GP-relative Initialized Data',
        '.xdata': 'Exception Information Section',
        '.wixburn': 'Wix section; see https://github.com/wixtoolset/wix3/blob/develop/src/burn/stub/StubSection.cpp',
        'BSS': 'Uninitialized Data Section  (Borland)',
        'CODE': 'Code Section (Borland)',
        'DATA': 'Data Section (Borland)',
        'DGROUP': 'Legacy data group section',
        'edata': 'Export Data Section',
        'idata': 'Initialized Data Section  (C RunTime)',
        'INIT': 'INIT section (drivers)',
        'minATL': 'Section that can be found inside some ARM PE files; purpose unknown',
        'PAGE': 'PAGE section (drivers)',
        'rdata': 'Read-only Data Section',
        'sdata': 'Initialized Data Section',
        'shared': 'Shared section',
        'Shared': 'Shared section',
        'testdata': 'section containing test data (can be found inside Visual Studio files)',
        'text': 'Alternative Code Section',
    }

    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)

    for section in pe.sections:
        sectionname = SectionNameToString(section.Name)
        if options.getdata == '':
            print('%d: %-10s %8d %f %s' % (counter, sectionname, section.SizeOfRawData, section.get_entropy(), dSections.get(sectionname, '')))
            if options.yara != None:
                for result in rules.match(data=section.get_data()):
                    print(' YARA rule: %s' % result.rule)
                    if options.yarastrings:
                        for stringdata in result.strings:
                            print('  %06x %s:' % (stringdata[0], stringdata[1]))
                            print('   %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                            print('   %s' % repr(stringdata[2]))
        elif int(options.getdata) == counter:
            StdoutWriteChunked(DumpFunction(section.get_data()))
        counter += 1

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

def FindAllPEFiles(data):
    result = []
    for position in FindAll(data, b'MZ'):
        if len(data[position:]) > 0x40:
            offset = struct.unpack('<I', (data[position + 0x3C:position + 0x40]))[0]
            if data[position + offset:position + offset + 2] == b'PE':
                result.append(position)
    return result

def PrefixIfNeeded(string, prefix=' '):
    if string == '':
        return string
    else:
        return prefix + string

class cHashCRC32():
    def __init__(self):
        self.crc32 = None

    def update(self, data):
        self.crc32 = zlib.crc32(data)

    def hexdigest(self):
        return '%08x' % (self.crc32 & 0xffffffff)

class cHashChecksum8():
    def __init__(self):
        self.sum = 0

    def update(self, data):
        if sys.version_info[0] >= 3:
            self.sum += sum(data)
        else:
            self.sum += sum(map(ord, data))

    def hexdigest(self):
        return '%08x' % (self.sum)

dSpecialHashes = {'crc32': cHashCRC32, 'checksum8': cHashChecksum8}

def GetHashObjects(algorithms):
    global dSpecialHashes

    dHashes = {}

    if algorithms == '':
        algorithms = os.getenv('DSS_DEFAULT_HASH_ALGORITHMS', 'md5')
    if ',' in algorithms:
        hashes = algorithms.split(',')
    else:
        hashes = algorithms.split(';')
    for name in hashes:
        if not name in dSpecialHashes.keys() and not name in hashlib.algorithms_available:
            print('Error: unknown hash algorithm: %s' % name)
            print('Available hash algorithms: ' + ' '.join([name for name in list(hashlib.algorithms_available)] + list(dSpecialHashes.keys())))
            return [], {}
        elif name in dSpecialHashes.keys():
            dHashes[name] = dSpecialHashes[name]()
        else:
            dHashes[name] = hashlib.new(name)

    return hashes, dHashes

def CalculateChosenHash(data):
    hashes, dHashes = GetHashObjects('')
    dHashes[hashes[0]].update(data)
    return dHashes[hashes[0]].hexdigest(), hashes[0]

def GetInfoCarvedFile(data, position):
    try:
        info = ''
        oPEtemp = pefile.PE(data=data[position:])
        if oPEtemp.is_dll():
            info = 'DLL'
        elif oPEtemp.is_exe():
            info = 'EXE'
        elif oPEtemp.is_driver():
            info = 'DRV'
        if oPEtemp.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE:
            info += ' 64-bit'
        else:
            info += ' 32-bit'
        overlayOffset = Fixed_get_overlay_data_start_offset(oPEtemp)
        dataPEFile = oPEtemp.write()
        if overlayOffset == None:
            lengthStripped = len(dataPEFile)
            lengthWithOverlay = len(dataPEFile)
            hashStripped, _ = CalculateChosenHash(dataPEFile)
        else:
            lengthStripped = len(dataPEFile[:overlayOffset])
            lengthWithOverlay = len(dataPEFile)
            hashStripped, _ = CalculateChosenHash(dataPEFile[:overlayOffset])
        info += ' 0x%08x %s 0x%08x' % (position + lengthStripped - 1, hashStripped, position + lengthWithOverlay - 1)
        if position + lengthWithOverlay == len(data):
            info += ' (EOF)'
        versionInfo = GetVersionInfo(oPEtemp)
        originalFilename = versionInfo.get(b'OriginalFilename', b'')
        exportDLLName = b''
        try:
            exportDLLName = oPEtemp.DIRECTORY_ENTRY_EXPORT.name
        except:
            pass
        info += ' %s %s' % (repr(originalFilename), repr(exportDLLName))
    except:
        info += ' parsing error %s' % repr(sys.exc_info()[1])
    return info

def SingleFile(filename, signatures, options):
    data = ReadFile(filename)
    if options.locate == 'P':
        for index, position in enumerate(FindAllPEFiles(data)):
            print('%d: 0x%08x%s' % (index + 1, position, PrefixIfNeeded(GetInfoCarvedFile(data, position))))
        return
    elif options.locate != '':
        try:
            index = int(options.locate)
        except:
            print('Error with option locate: %s' % options.locate)
            return
        index -= 1
        locations = FindAllPEFiles(data)
        if index < 0 or index >= len(locations):
            print('Error with index option locate: %s' % options.locate)
            return
        data = data[locations[index]:]
    if options.overview == 'r':
        Resources(data, options)
    elif options.overview == 's':
        Sections(data, options)
    elif options.getdata != '':
        pe = pefile.PE(data=data)
        DumpFunction = GetDumpFunction(options)
        if options.getdata == 'o': # overlay
            overlayOffset = Fixed_get_overlay_data_start_offset(pe)
            if overlayOffset == None:
                print('No overlay')
            else:
                StdoutWriteChunked(DumpFunction(C2SIP2(pe.write()[overlayOffset:])))
        elif options.getdata == 's': # strip
            overlayOffset = Fixed_get_overlay_data_start_offset(pe)
            if overlayOffset == None:
                StdoutWriteChunked(DumpFunction(C2SIP2(pe.write())))
            else:
                StdoutWriteChunked(DumpFunction(C2SIP2(pe.write()[:overlayOffset])))
        else:
            parsed = ParseGetData(options.getdata)
            if parsed == None:
                print('Error getdata syntax error: %s' % options.getdata)
                return
            StdoutWriteChunked(DumpFunction(pe.get_data(parsed[0], parsed[1])))
    else:
        SingleFileInfo(filename, data, signatures, options)

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
            for oStringTableEntry in oFileInfoEntry[0].StringTable:
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
        pe = pefile.PE(data=ReadFile(filename))
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
            sys.exit()

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
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-d', '--db', default='', help='the PeID user db file, default userdb.txt in same directory as pecheck')
    oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan folder')
    oParser.add_option('-e', '--entropy', type=float, default=7.0, help='the minimum entropy value for a file to be listed in scan mode (default 7.0)')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file or directory to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-g', '--getdata', type=str, default='', help='Get data from the PE file (example 0x1234,0x100)')
    oParser.add_option('-D', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-S', '--strings', action='store_true', default=False, help='perform strings dump')
    oParser.add_option('-o', '--overview', type=str, default='', help='Accepted value: r for overview of resources, s for sections')
    oParser.add_option('-l', '--locate', type=str, default='', help='Locate PE files inside binary data (P for list of MZ/PE headers)')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='Verbose output with YARA rules')
    (options, args) = oParser.parse_args(GetArgumentsUpdatedWithEnvironmentVariable('PECHECK_OPTIONS'))

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if len(args) > 1 or options.overview != '' and options.overview != 'r' and options.overview != 's':
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
            if os.path.exists(dbfile):
                signatures = peutils.SignatureDatabase(dbfile)
            else:
                signatures = 'Error: signature database missing'
        except:
            signatures = 'Error: while reading the signature database: %s' % sys.exc_info()[1].message
        if len(args) == 0:
            SingleFile('', signatures, options)
        elif options.scan:
            oLogger = CSVLogger('pecheck', ('Filename', 'Entropy', 'Sections', 'Executable sections', 'Executable and writable sections', 'Size AuthentiCode', 'Stored CRC', 'Calculated CRC', 'CRC anomaly', 'Compile date', 'CompanyName', 'ProductName', 'MD5'))
            ScanFiles(args[0], signatures, options.entropy)
        else:
            SingleFile(args[0], signatures, options)

if __name__ == '__main__':
    Main()
