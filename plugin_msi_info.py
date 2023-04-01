#!/usr/bin/env python

__description__ = 'MSI summary plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2023/04/01'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2023/02/25: start
  2023/02/26: continue
  2023/02/26: 0.0.2 continue
  2023/02/28: continue
  2023/03/23: 0.0.2 added indicator and cCab
  2023/04/01: 0.0.3 detect signature streams, repr streamname, chosenhash

Todo:
"""

import optparse

# https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf
class cCab(object):

    def __init__(self, data):
        self.data = data
        oStruct = cStruct(data)
        oCFHeader = oStruct.UnpackNamedtuple('<IIIIIIBBHH', 'cfheader', 'signature reserved1 cbCabinet reserved2 coffFiles reserved3 versionMinor versionMajor cFolders cFiles')
        oStruct = cStruct(data[oCFHeader.coffFiles:])
        self.files = []
        typename = 'cffile'
        field_names = 'cbFile uoffFolderStart iFolder date time attribs szName'
        for i in range(oCFHeader.cFiles):
            oCFFile = oStruct.UnpackNamedtuple('<IIHHHHz', typename, field_names)
            self.files.append(oCFFile)

def Convert(character):
    code = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._!'
    number = ord(character)
    if number >= 0x3800 and number < 0x4800:
        return code[(number - 0x3800) & 0x3F] + code[((number - 0x3800) >> 6) & 0x3F]
    elif number >= 0x4800 and number <= 0x4840:
        return code[number - 0x4800]
    else:
        return character

def StreamToRows(data, columns):
    rowsize = 0
    for column in columns:
        rowsize += struct.calcsize(column)
    cntRows = int(len(data) / rowsize)
#    print('Number of rows: %d' % cntRows)
    oData = cStruct(data)
    dColumns = {index: [] for index, column in enumerate(columns)}
    for index, column in enumerate(columns):
        for row in range(cntRows):
            dColumns[index].append(oData.Unpack(column))
    table = []
    for rowIndex in range(cntRows):
        row = []
        for column in range(len(columns)):
            row.append(dColumns[column][rowIndex])
        table.append(row)
    return table

def MagicSub(data):
    if data[:2] == b'MZ':
        result = 'PE File'
    elif data[:4] == b'MSCF':
        result = 'CAB File'
    elif data[:4] == b'\xff\xd8\xff\xe0':
        result = 'JPEG'
    elif data[:4] == b'\x00\x00\x01\x00':
        result = 'ICO'
    elif data[:4] == b'\x00\x00\x02\x00':
        result = 'CUR'
    elif data[:2] == b'BM':
        result = 'BMP'
    else:
        result = repr(data[:8])
    return result

def Magic(data):
    hashvalue, hashname = CalculateChosenHash(data)
    return '%s %s: %s' % (MagicSub(data), hashname, hashvalue)

class cStrings(object):
    def __init__(self, dStreams):
        oStringsData = cStruct(dStreams['!_StringData'][0])
        oStringsPool = cStruct(dStreams['!_StringPool'][0])
        self.dStrings = {}
        self.dReferenceCounterStored = {}
        self.dReferenceCounter = {}
        self.codepage, self.unknownSuspectFormatIdentifier = oStringsPool.Unpack('<HH')
        counter = 0
        while oStringsPool.Length() > 0:
            counter += 1
            size, referenceCountStored = oStringsPool.Unpack('<HH')
            if size > 0:
                stringBytes = oStringsData.GetBytes(size)
            else:
                stringBytes = b''
            self.dStrings[counter] = stringBytes
            self.dReferenceCounterStored[counter] = referenceCountStored

    def Get(self, index):
        self.dReferenceCounter[index] = self.dReferenceCounter.get(index, 0) + 1
        return self.dStrings[index]

# https://doxygen.reactos.org/db/de4/msipriv_8h.html
def ParseColumnAttributes(number):
    if number < 0x8000:
        return '<ERROR>'
    result = []
    if number & 0x2000 == 0x2000:
        result.append('Key:Y')
    else:
        result.append('Key:N')
    if number & 0x1000 == 0x1000:
        result.append('Nullable:Y')
    else:
        result.append('Nullable:N')
    rest = number & 0x0FFF
    dTypes = {
        0x104: 'DoubleInteger',
        0x502: 'Integer',
#        0xD48: 'Identifier',
#        0xDFF: 'Condition',
#        0xFFF: 'Text',
        0xD: 'String',
        0xF: 'StringLocalized',
        0x9: 'Binary',
    }
    if rest in dTypes:
        result.append('Type:%s' % dTypes[rest])
    else:
        type = (number & 0x0F00) >> 8
        result.append('Type:%s' % dTypes.get(type, '%x' % type))
        result.append('Length:%02x' % (number & 0x00FF))
    return ' '.join(result)

def ColumnFormats(dTable):
    result = []
    for value in dTable.values():
        value1 = value[1] & 0x0FFF
        value2 = value[1] & 0x0FF
        if value1 >= 0x0800:
            result.append('<H')
        elif value2 == 0x02:
            result.append('<H')
        elif value2 == 0x04:
            result.append('<I')
        else:
            raise
    return result

class cMSI(cPluginParentOle):
    indexQuiet = True
    name = 'MSI summary plugin'

    def PreProcess(self):
        self.StringsData = None
        self.StringsPool = None
        self.dStreams = {}
        self.counter = 1

    def Process(self, name, stream):
        decodedName = '/'.join(map(lambda x: ''.join([Convert(y) for y in x]), name))
        self.dStreams[decodedName] = [stream, self.counter]
        self.counter += 1

    def PostProcess(self):
        oParser = optparse.OptionParser()
        oParser.add_option('-V', '--verbose', action='store_true', default=False, help='Verbose output')
        (options, args) = oParser.parse_args(self.options.split(' '))

        print('Beta version: the format of the output will change with upcoming releases!')
        streamsProcessed = []

        print('Streams:')
        for key, [data, index] in self.dStreams.items():
            if key not in streamsProcessed:
                print('%3d %10d %s' % (index, len(data), key))
        print()

        oStrings = cStrings(self.dStreams)
        if options.verbose:
            print('Strings:')
            print('Code page: %d' % oStrings.codepage)
            for key, value in oStrings.dStrings.items():
                print('%04x %s' % (key, value))

        streamsProcessed.append('!_StringData')
        streamsProcessed.append('!_StringPool')

        if options.verbose:
            print('!_Columns')
        streamsProcessed.append('!_Columns')
        dTables = {}
        columns = StreamToRows(self.dStreams['!_Columns'][0], ['<H', '<H', '<H', '<H'])
        for row in columns:
            tableStringID, columnNumber, columnStringID, columnAttributes = row
            tableString = oStrings.Get(tableStringID)
            columnString = oStrings.Get(columnStringID)
            if options.verbose:
                print('%s %04x %s %04x %s' % (tableString, columnNumber, columnString, columnAttributes, ParseColumnAttributes(columnAttributes)))
            if not tableString in dTables:
                dTables[tableString] = {}
            dTables[tableString][columnString] = [columnNumber, columnAttributes]

        print('Tables:')
        tables = []
        oTables = cStruct(self.dStreams['!_Tables'][0])
        while oTables.Length() > 0:
            tableName = oStrings.Get(oTables.Unpack('<H'))
            tables.append(tableName)
            print(tableName)
        streamsProcessed.append('!_Tables')
        print()

        # https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
        dCustomActionTypes = {
            1: b'DLL file stored in a Binary table stream.',
            2: b'EXE file stored in a Binary table stream.',
            5: b'JScript file stored in a Binary table stream.',
            6: b'VBScript file stored in a Binary table stream.',
            17: b'DLL file that is installed with a product.',
            18: b'EXE file that is installed with a product.',
            19: b'Displays a specified error message and returns failure, terminating the installation.',
            21: b'JScript file that is installed with a product.',
            22: b'VBScript file that is installed with a product.',
            34: b'EXE file having a path referencing a directory.',
            35: b'Directory set with formatted text.',
            37: b'JScript text stored in this sequence table.',
            38: b'VBScript text stored in this sequence table.',
            50: b'EXE file having a path specified by a property value.',
            51: b'Property set with formatted text.',
            53: b'JScript text specified by a property value.',
            54: b'VBScript text specified by a property value.',
        }

        for tableName in tables:
            streamName = '!' + tableName.decode()
            if streamName in self.dStreams:
                streamsProcessed.append(streamName)
                print('Stream: %s' % streamName)
                dTable = dTables[tableName]
                columnFormats = ColumnFormats(dTable)
#                print(columnFormats)
                rows = StreamToRows(self.dStreams[streamName][0], columnFormats)
                print(b','.join(dTable.keys()))
                for row in rows:
                    values = []
                    for index, value in enumerate(row):
                        if columnFormats[index] == '<I':
                            if value == 0:
                                values.append(b'0')
                            else:
                                values.append(b'%d' % (value - 0x80000000))
                        elif value in oStrings.dStrings:
                            values.append(oStrings.Get(value))
                        elif value == 0:
                            values.append(b'0')
                        else:
                            values.append(b'%d' % (value - 0x8000))
                    if streamName == '!MsiFileHash':
                        hash = struct.pack('<I', row[2] ^ 0x80000000) + struct.pack('<I', row[3] ^ 0x80000000) + struct.pack('<I', row[4] ^ 0x80000000) + struct.pack('<I', row[5] ^ 0x80000000)
                        values.append(b' -> MD5: %s' % binascii.b2a_hex(hash))
                    if streamName == '!CustomAction':
                        customAction = row[1] & 0x3F
                        if customAction in dCustomActionTypes:
                            values.append(b' -> %d: %s' % (customAction, dCustomActionTypes[customAction]))
                    print(b','.join(values))
                print()

        if options.verbose:
            print('String table stats:')
            print('Stored reference count = 0:')
            for key, value in oStrings.dReferenceCounterStored.items():
                if value == 0:
                    print('%d %s' % (key, oStrings.dStrings[key]))
            print('Unreferenced:')
            for key, value in oStrings.dReferenceCounter.items():
                if value == 0:
                    print('%d %s' % (key, oStrings.dStrings[key]))
            print('Compare:')
            for key, value in oStrings.dReferenceCounterStored.items():
                if not key in oStrings.dReferenceCounter:
                    pass
                elif value != oStrings.dReferenceCounter[key]:
                    print('%d %d %d %s' % (key, value, oStrings.dReferenceCounter[key], oStrings.dStrings[key]))
            print()

        print('Remaining streams:')
        for key, [data, index] in self.dStreams.items():
            if key not in streamsProcessed:
                filetype = MagicSub(data)
                if filetype in ['BMP', 'JPEG', 'ICO', 'CUR']:
                    indicator = ' '
                elif filetype in ['PE File', 'CAB File']:
                    indicator = '!'
                elif key in ['\x05SummaryInformation', '\x05DocumentSummaryInformation', '\x05DigitalSignature', '\x05MsiDigitalSignatureEx']:
                    indicator = ' '
                else:
                    indicator = '?'
                print('%2d %s %8d %s %s' % (index, indicator, len(data), repr(key), Magic(data)))
                if filetype == 'CAB File':
                    try:
                        oCab = cCab(data)
                        for item in oCab.files:
                            print('               %8d %s' % (item.cbFile, repr(item.szName)))
                    except:
                        print('               error parsing CAB file')

AddPlugin(cMSI)
