#!/usr/bin/env python

__description__ = 'Analyze RTF files'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2017/02/11'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/09/01: start
  2015/09/02: continue
  2015/09/09: added --cut ...l and bytes appended after last group
  2015/09/11: added re.I for hex regexes
  2015/09/12: CutData refactoring
  2015/09/14: added YARA support
  2015/09/15: added basic HEX deobfuscation (options -F and -S)
  2015/11/18: added support for -c :-number
  2016/01/23: added support to ExtractHex for obfuscated hex code; updated CutData
  2016/01/23: added option -i
  2016/07/23: 0.0.2 continue; sample 1B8113DC81489FF37202A1E038A7781D
  2016/07/24: continue
  2016/07/26: continue
  2016/07/27: continue
  2016/07/30: 0.0.3 added option recursionlimit
  2016/08/09: 0.0.4 refactoring
  2016/08/12: continue
  2017/02/11: added \dde000... handling; added option -E

Todo:
"""

import optparse
import sys
import os
import zipfile
import cStringIO
import binascii
import textwrap
import re
import string
import hashlib
import cStringIO

try:
    import yara
except:
    pass

dumplinelength = 16
MALWARE_PASSWORD = 'infected'

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

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

def AddPlugin(cClass):
    global plugins

    plugins.append(cClass)

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cPluginParent():
    macroOnly = False

def LoadPlugins(plugins, verbose):
    if plugins == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for plugin in sum(map(ProcessAt, plugins.split(',')), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if os.path.dirname(plugin) == '':
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec open(plugin, 'r') in globals(), globals()
        except Exception as e:
            print('Error loading plugin: %s' % plugin)
            if verbose:
                raise e

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, verbose):
    if decoders == '':
        return
    scriptPath = os.path.dirname(sys.argv[0])
    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec open(decoder, 'r') in globals(), globals()
        except Exception as e:
            print('Error loading decoder: %s' % decoder)
            if verbose:
                raise e

class cIdentity(cDecoderParent):
    name = 'Identity function decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ''

def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()

class cIteminfo():
    def __init__(self, level, beginPosition, endPosition, countChildren):
        self.level = level
        self.beginPosition = beginPosition
        self.endPosition = endPosition
        self.countChildren = countChildren

def BuildTree(rtfdata, level, index, sequence, options):
    children = 0
    level += 1
    if index >= len(rtfdata):
        return None
    if rtfdata[index] != '{':
        error = 'Parser error: Expected character {'
        print(error)
        raise Exception(error)
    start = index
    oIteminfo = cIteminfo(level, start, None, None)
    sequence.append(oIteminfo)
    index += 1
    while index < len(rtfdata):
        if rtfdata[index] == '{' and (index == 0 or rtfdata[index - 1] != '\\'):
            index = BuildTree(rtfdata, level, index, sequence, options)
            children += 1
        elif rtfdata[index] == '}' and (index == 0 or rtfdata[index - 1] != '\\'):
            oIteminfo.endPosition = index
            oIteminfo.countChildren = children
            return index + 1
        else:
            index += 1
    if options.select == '':
        print('Parser warning: Missing terminating character } level = %d' % level)
    oIteminfo.endPosition = index
    oIteminfo.countChildren = children
    return index

def Trimdde(data):
    if not data.startswith('\r\n\\dde'):
        return data
    data = data[6:]
    counter = 0
    while data[counter] == '0' and counter < 250:
        counter += 1
    return data[counter:]

def ExtractHex(data):
    data = Trimdde(data)
    if data.startswith('\r\n\\dde'):
        print(repr(data[0:40]))
    backslash = False
    backslashtext = ''
    hexstring = [cStringIO.StringIO()]
    countUnexpectedCharacters = 0
    binstatus = 0
    binnumber = ''
    bintext = ''
    i = 0
    while i < len(data):
        char = data[i]
        if binstatus > 0:
            if binstatus == 1:
                if char in string.digits:
                    binnumber += char
                elif char in string.whitespace:
                    pass
                else:
                    binstatus = 2
                    if binnumber == '':
                        binint = 0
                    else:
                        binint = int(binnumber)
                    bintext = ''
                    if binint == 0:
                        binstatus = 0
                    i -= 1
            elif binstatus == 2:
                    bintext += char
                    binint -= 1
                    if binint == 0:
                        binstatus = 0
                        hexstring.append(['bin', bintext])
                        hexstring.append(cStringIO.StringIO())
                        binnumber = ''
                        bintext = ''
        elif backslash:
            if char in string.letters or char in string.digits or char == '-':
                backslashtext += char
                if backslashtext == '\\bin':
                    binstatus = 1
                    binnumber = ''
                    backslash = False
                    backslashtext = ''
            elif backslashtext == '\\':
                backslash = False
                backslashtext = ''
            else:
#                if backslashtext != '\\-':
#                    print(repr(backslashtext))
                backslash = False
                backslashtext = ''
                i -= 1
        elif char == '\\':
            backslash = True
            backslashtext = char
        elif char in string.hexdigits:
            hexstring[-1].write(char)
        elif char in string.whitespace:
            pass
        elif char in ['{', '}']:
            pass
        else:
            countUnexpectedCharacters += 1
#            print(hexstring)
#            print(repr(char))
#            if not char in ['\0']:
#                raise('xxx')
        i += 1
    return [IFF(isinstance(x, list), x, lambda: x.getvalue()) for x in hexstring], countUnexpectedCharacters

def ReadDWORD(data):
    if len(data) < 4:
        return None, None
    return ord(data[0]) + ord(data[1]) *0x100 + ord(data[2]) *0x10000 + ord(data[3]) *0x1000000, data[4:]

def ExtractOleInfo(data):
    word1, data = ReadDWORD(data)
    if word1 == None or word1 != 0x00000501:
        return []
    word2, data = ReadDWORD(data)
    if word2 == None or word2 != 0x00000002:
        return []
    word3, data = ReadDWORD(data)
    if word3 == None:
        return []
    if word3 > 0 and word3 <= len(data):
        name = data[:word3]
        data = data[word3:]
    else:
        return []
    word4, data = ReadDWORD(data)
    if word4 == None or word4 != 0x00000000:
        return []
    word5, data = ReadDWORD(data)
    if word5 == None or word5 != 0x00000000:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []

    return [name, 6*4 + word3, sizeEmbedded]

def Info(data):
    result = ExtractOleInfo(data)
    if result == []:
        return 'Error: extraction failed'
    return 'Name: %s\nPosition embedded: %08x\nSize embedded: %08x\nmd5: %s\nmagic: %s\n' % (repr(result[0]), result[1], result[2], hashlib.md5(data[result[1]:result[1] + result[2]]).hexdigest(), binascii.b2a_hex(data[result[1]:result[1] + 4]))

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

def ExtractPackage(data):
    result = ExtractOleInfo(data)
    return data[result[1]:result[1] + result[2]]

def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

def ParseCutTerm(argument):
    if argument == '':
        return CUTTERM_NOTHING, None, ''
    oMatch = re.match(r'\-?0x([0-9a-f]+)', argument, re.I)
    if oMatch == None:
        oMatch = re.match(r'\-?(\d+)', argument)
    else:
        value = int(oMatch.group(1), 16)
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-]\d+)?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[\'(.+?)\'\](\d+)?([+-]\d+)?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        return CUTTERM_FIND, (oMatch.group(1), int(Replace(oMatch.group(2), {None: '1'})), int(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

def ParseCutArgument(argument):
    type, value, remainder = ParseCutTerm(argument.strip())
    if type == CUTTERM_NOTHING:
        return CUTTERM_NOTHING, None, CUTTERM_NOTHING, None
    elif type == None:
        if remainder.startswith(':'):
            typeLeft = CUTTERM_NOTHING
            valueLeft = None
            remainder = remainder[1:]
        else:
            return None, None, None, None
    else:
        typeLeft = type
        valueLeft = value
        if typeLeft == CUTTERM_POSITION and valueLeft < 0:
            return None, None, None, None
        if typeLeft == CUTTERM_FIND and valueLeft[1] == 0:
            return None, None, None, None
        if remainder.startswith(':'):
            remainder = remainder[1:]
        else:
            return None, None, None, None
    type, value, remainder = ParseCutTerm(remainder)
    if type == CUTTERM_POSITION and remainder == 'l':
        return typeLeft, valueLeft, CUTTERM_LENGTH, value
    elif type == None or remainder != '':
        return None, None, None, None
    elif type == CUTTERM_FIND and value[1] == 0:
        return None, None, None, None
    else:
        return typeLeft, valueLeft, type, value

def Find(data, value, nth):
    position = -1
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return stream

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return stream

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ''
        positionBegin += valueLeft[2]
    else:
        raise Exception("Unknown value typeLeft")

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1])
        if positionEnd == -1:
            return ''
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return stream[positionBegin:positionEnd]

def HexDecode(hexstream, options):
    if hexstream == None:
        return ''
    result = ''
    for entry in hexstream:
        if isinstance(entry, str):
            if len(entry) % 2 == 1:
                if options.hexshift:
                    hexdata = '0' + entry
                else:
                    hexdata = entry + '0'
            elif options.hexshift:
                hexdata = '0' + entry + '0'
            else:
                hexdata = entry
            result += binascii.a2b_hex(hexdata)
        else:
            result += entry[1]
    return result

def HexDecodeIfRequested(info, options):
    if options.hexdecode:
        hexstream = info.hexstring
        if hexstream == None:
            return info.content
        return HexDecode(hexstream, options)
    else:
        return info.content

def HexBinCount(hexstream):
    hexcount = 0
    bincount = 0
    for entry in hexstream:
        if isinstance(entry, str):
            hexcount += len(entry)
        else:
            bincount += len(entry[1])
    return hexcount, bincount

class cAnalysis():
    def __init__(self, index, leader, level, beginPosition, endPosition, countChildren, countUnexpectedCharacters, controlWord, content, hexstring, oleInfo):
        self.index = index
        self.leader = leader
        self.level = level
        self.beginPosition = beginPosition
        self.endPosition = endPosition
        self.countChildren = countChildren
        self.countUnexpectedCharacters = countUnexpectedCharacters
        self.controlWord = controlWord
        self.content = content
        self.hexstring = hexstring
        self.oleInfo = oleInfo

def GenerateMAGIC(data):
    return binascii.b2a_hex(data) + ' ' + ''.join([IFF(ord(c) >= 32, c, '.') for c in data])

def RTFSub(oStringIO, prefix, rules, options):
    global plugins
    global decoders

    if options.filter != '':
        if not options.filter in ['O', 'h']:
            print('Unknown filter: %s' % options.filter)
            return

    returnCode = 0

    sys.setrecursionlimit(options.recursionlimit)

    counter = 1
    rtfdata = oStringIO.read()
    if not rtfdata.startswith('{'):
        print('This file does not start with an opening brace: {\nCheck if it is an RTF file.\nMAGIC: %s' % GenerateMAGIC(rtfdata[0:4]))
        return -1
    sequence = []
    BuildTree(rtfdata, 0, 0, sequence, options)
    remainder = rtfdata[sequence[0].endPosition + 1:]
    if len(remainder) > 0:
        sequence.append(cIteminfo(0, sequence[0].endPosition + 1, len(rtfdata) - 1, 0))
    dAnalysis = {}
    for oIteminfo in sequence:
        oMatch = re.match(r'(\\\*)?\\[a-z]+(-?[0-9]+)? ?', rtfdata[oIteminfo.beginPosition + 1:])
        controlWord = ''
        if oMatch != None:
            controlWord = oMatch.group(0)
        beginContent = oIteminfo.beginPosition + 1 + len(controlWord)
        endContent = oIteminfo.endPosition - 1
        if beginContent < endContent:
            content = rtfdata[beginContent:endContent + 1]
        else:
            content = ''
        hexstring, countUnexpectedCharacters = ExtractHex(content)
        leader = '%sLevel %2d                      ' % (' ' * (oIteminfo.level - 1), oIteminfo.level)
        dAnalysis[counter] = cAnalysis(counter, leader, oIteminfo.level, oIteminfo.beginPosition, oIteminfo.endPosition, oIteminfo.countChildren, countUnexpectedCharacters, controlWord, content, hexstring, ExtractOleInfo(HexDecode(hexstring, options)))
        counter += 1

    if options.select == '':
        for counter in range(1, len(dAnalysis) + 1):
            hexcount, bincount = HexBinCount(dAnalysis[counter].hexstring)
            if options.filter == '' or options.filter == 'O' and dAnalysis[counter].oleInfo != [] or options.filter == 'h' and hexcount > 0:
                line = '%5d %s c=%5d p=%08x l=%8d h=%8s b=%8s %s u=%8d %s' % (counter, dAnalysis[counter].leader[0:15], dAnalysis[counter].countChildren, dAnalysis[counter].beginPosition, dAnalysis[counter].endPosition - dAnalysis[counter].beginPosition, hexcount, bincount, IFF(dAnalysis[counter].oleInfo != [], 'O', ' '), dAnalysis[counter].countUnexpectedCharacters, dAnalysis[counter].controlWord.strip())
                if dAnalysis[counter].controlWord.strip() == '\\*\\objclass':
                    line += ' ' + dAnalysis[counter].content
                linePrinted = False
                if options.yara == None:
                    print(line)
                    linePrinted = True
                elif dAnalysis[counter].content != None:
                    stream = HexDecodeIfRequested(dAnalysis[counter], options)
                    oDecoders = [cIdentity(stream, None)]
                    for cDecoder in decoders:
                        try:
                            oDecoder = cDecoder(stream, options.decoderoptions)
                            oDecoders.append(oDecoder)
                        except Exception as e:
                            print('Error instantiating decoder: %s' % cDecoder.name)
                            if options.verbose:
                                raise e
                            return returnCode
                    for oDecoder in oDecoders:
                        while oDecoder.Available():
                            for result in rules.match(data=oDecoder.Decode()):
                                if not linePrinted:
                                    print(line)
                                    linePrinted = True
                                print('               YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (stream decoder: %s)' % oDecoder.Name()), result.rule))
                                if options.yarastrings:
                                    for stringdata in result.strings:
                                        print('               %06x %s:' % (stringdata[0], stringdata[1]))
                                        print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                        print('                %s' % repr(stringdata[2]))
    else:
        if len(decoders) > 1:
            print('Error: provide only one decoder when using option select')
            return returnCode
        if options.dump:
            DumpFunction = lambda x:x
            IfWIN32SetBinary(sys.stdout)
        elif options.hexdump:
            DumpFunction = HexDump
        elif options.info:
            DumpFunction = Info
        else:
            DumpFunction = HexAsciiDump
        if options.extract:
            ExtractFunction = ExtractPackage
        else:
            ExtractFunction = lambda x:x
        StdoutWriteChunked(DumpFunction(ExtractFunction(DecodeFunction(decoders, options, CutData(HexDecodeIfRequested(dAnalysis[int(options.select)], options), options.cut)))))

    return returnCode

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

def RTFDump(filename, options):
    global plugins
    plugins = []
    LoadPlugins(options.plugins, True)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, True)

    returnCode = 0

    rules = None
    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return returnCode
        rules = YARACompile(options.yara)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    returnCode = RTFSub(oStringIO, '', rules, options)

    return returnCode

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-H', '--hexdecode', action='store_true', default=False, help='decode hexadecimal data; append 0 in case of uneven number of hexadecimal digits')
    oParser.add_option('-S', '--hexshift', action='store_true', default=False, help='shift one nibble')
    oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='only print output from plugins')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file or directory to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-E', '--extract', action='store_true', default=False, help='extract package')
    oParser.add_option('-f', '--filter', type=str, default='', help='filter')
    oParser.add_option('--recursionlimit', type=int, default=2000, help='set recursionlimit for Python (default 2000)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-c) is invalid: %s' % options.cut)
        return 0

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    elif len(args) == 0:
        return RTFDump('', options)
    else:
        return RTFDump(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
