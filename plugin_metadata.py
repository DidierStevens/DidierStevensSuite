#!/usr/bin/env python

__description__ = 'metadata plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2022/10/27'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/02/28: start
  2022/04/25: start again for second propertyset (VSTO files)
  2022/04/26: refactor
  2022/09/24: 0.0.2 added ParseASN
  2022/09/25: continue
  2022/10/09: added PropertySetSystemIdentifier
  2022/10/27: added options: option -s

Todo:
  implement remaining types
"""

import datetime

try:
    from pyasn1.codec.der import decoder as der_decoder
except ImportError:
    print(' Signature present but error importing pyasn1 module')
try:
    from pyasn1_modules import rfc2315
except ImportError:
    print(' Signature present but error importing pyasn1_modules module')

# [MS-OLEPS].pdf
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/bf7aeae8-c47a-4939-9f45-700158dac3bc

DICTIONARY_PROPERTY_IDENTIFIER = 0x00000000
CODEPAGE_PROPERTY_IDENTIFIER   = 0x00000001
LOCALE_PROPERTY_IDENTIFIER     = 0x80000000
BEHAVIOR_PROPERTY_IDENTIFIER   = 0x80000003

# https://www.cryptosys.net/pki/manpki/pki_distnames.html
def PrintComponents(obj):
    dOIDs = {
        '2.5.4.3': 'CN',
        '2.5.4.4': 'SN',
        '2.5.4.5': 'SERIALNUMBER',
        '2.5.4.6': 'C',
        '2.5.4.7': 'L',
        '2.5.4.8': 'S', # or ST
        '2.5.4.9': 'STREET',
        '2.5.4.10': 'O',
        '2.5.4.11': 'OU',
        '2.5.4.12': 'T', # or  or TITLE
        '2.5.4.42': 'G', #  or GN
        '1.2.840.113549.1.9.1': 'E',
        '0.9.2342.19200300.100.1.1': 'UID',
        '0.9.2342.19200300.100.1.25': 'DC',
    }

    result = []
    for component1 in obj.components[0]:
        for component2 in component1:
            oid = list(component2.values())[0].prettyPrint()
            value = list(component2.values())[1][2:]
            result.append('%s=%s' % (dOIDs.get(oid, oid), value))
    return ','.join(result)

def ParseASN(data):
    position = data.find(b'\x30')
    signature = data[position:]

    contentInfo, _ = der_decoder.decode(signature, asn1Spec=rfc2315.ContentInfo())
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
    serialNumber = content['signerInfos'][0]['issuerAndSerialNumber']['serialNumber']
    issuer = None
    subject = None
    for f in content['certificates']:
        if f['certificate']['tbsCertificate']['serialNumber'] == serialNumber:
            certificate = f['certificate']['tbsCertificate']
            issuer = PrintComponents(certificate['issuer'])
            subject = PrintComponents(certificate['subject'])
    return issuer, subject

class cCONSTANTS(object):
    def __init__(self):
        self.dCONSTANTS = {}

    def AddValue(self, name, value):
        self.dCONSTANTS[name] = value

    def Eval(self):
        for key, value in self.dCONSTANTS.items():
            exec('%s = %d' % (key, value), globals())

    def Lookup(self, value, default=None):
        for key, value2 in self.dCONSTANTS.items():
            if value == value2:
                return key
        return default

oCONSTANTS = cCONSTANTS()
oCONSTANTS.AddValue('VT_EMPTY', 0x0000)
oCONSTANTS.AddValue('VT_NULL', 0x0001)
oCONSTANTS.AddValue('VT_I2', 0x0002)
oCONSTANTS.AddValue('VT_I4', 0x0003)
oCONSTANTS.AddValue('VT_R4', 0x0004)
oCONSTANTS.AddValue('VT_R8', 0x0005)
oCONSTANTS.AddValue('VT_CY', 0x0006)
oCONSTANTS.AddValue('VT_DATE', 0x0007)
oCONSTANTS.AddValue('VT_BSTR', 0x0008)
oCONSTANTS.AddValue('VT_ERROR', 0x000A)
oCONSTANTS.AddValue('VT_BOOL', 0x000B)
oCONSTANTS.AddValue('VT_DECIMAL', 0x000E)
oCONSTANTS.AddValue('VT_I1', 0x0010)
oCONSTANTS.AddValue('VT_UI1', 0x0011)
oCONSTANTS.AddValue('VT_UI2', 0x0012)
oCONSTANTS.AddValue('VT_UI4', 0x0013)
oCONSTANTS.AddValue('VT_I8', 0x0014)
oCONSTANTS.AddValue('VT_UI8', 0x0015)
oCONSTANTS.AddValue('VT_INT', 0x0016)
oCONSTANTS.AddValue('VT_UINT', 0x0017)
oCONSTANTS.AddValue('VT_LPSTR', 0x001E)
oCONSTANTS.AddValue('VT_LPWSTR', 0x001F)
oCONSTANTS.AddValue('VT_FILETIME', 0x0040)
oCONSTANTS.AddValue('VT_BLOB', 0x0041)
oCONSTANTS.AddValue('VT_STREAM', 0x0042)
oCONSTANTS.AddValue('VT_STORAGE', 0x0043)
oCONSTANTS.AddValue('VT_STREAMED_OBJECT', 0x0044)
oCONSTANTS.AddValue('VT_STORED_OBJECT', 0x0045)
oCONSTANTS.AddValue('VT_BLOB_OBJECT', 0x0046)
oCONSTANTS.AddValue('VT_CF', 0x0047)
oCONSTANTS.AddValue('VT_CLSID', 0x0048)
oCONSTANTS.AddValue('VT_VERSIONED_STREAM', 0x0049)
oCONSTANTS.AddValue('VT_VECTOR', 0x1000)
oCONSTANTS.AddValue('VT_ARRAY', 0x2000)
oCONSTANTS.Eval()

dVTNumbers = {
    VT_I2:  '<h',
    VT_I4:  '<i',
    VT_R4:  '<f',
    VT_R8:  '<d',
    VT_I1: '<b',
    VT_UI1: '<B',
    VT_UI2: '<H',
    VT_UI4: '<I',
    VT_I8:  '<q',
    VT_UI8:  '<Q',
    VT_INT: '<i',
    VT_UINT: '<I',
}

dGUIDs = {
    '{F29F85E0-4FF9-1068-AB91-08002B27B3D9}' : 'FMTID_SummaryInformation',
    '{D5CDD502-2E9C-101B-9397-08002B2CF9AE}' : 'FMTID_DocSummaryInformation',
    '{D5CDD505-2E9C-101B-9397-08002B2CF9AE}' : 'FMTID_UserDefinedProperties'
}

def GUID2String(data):
    return '{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}' % tuple(data[3::-1] + data[5:3:-1] + data[7:5:-1] + data[8:16])

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def Unpack(self, format):
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        self.data = self.data[length:]
        return result

    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)

def CreateFILETIME(strDateTime):
    return int((datetime.datetime.strptime(strDateTime, '%Y-%m-%d %H:%M:%S') - datetime.datetime(1601, 1, 1, 0, 0, 0)).total_seconds() * 10000000)

def FILETIME2String(ft):
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
    return (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds = (ft - EPOCH_AS_FILETIME) // 10)).isoformat()

class cMetadata(cPluginParent):
    macroOnly = False
    name = 'Metadata plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def AttributeName(self, identifier, dPropertyNames={}):
        if identifier in dPropertyNames:
            return dPropertyNames[identifier]
        elif identifier > len(self.attributeNames):
            if identifier == LOCALE_PROPERTY_IDENTIFIER:
                return 'LocaleProperty'
            elif identifier == CODEPAGE_PROPERTY_IDENTIFIER:
                return 'CodePageProperty'
            elif identifier == BEHAVIOR_PROPERTY_IDENTIFIER:
                return 'BehaviorProperty'
            else:
                return '%04x' % identifier
        else:
            return self.attributeNames[identifier - 1]

    def ParseTypedPropertyValue(self, oStructTypedPropertyValue):
        type, padding = oStructTypedPropertyValue.Unpack('<HH')
        if type == VT_LPSTR:
            return True, type, oStructTypedPropertyValue.GetString('<I').decode('latin').rstrip('\x00')
        elif type == VT_LPWSTR:
            length = oStructTypedPropertyValue.Unpack('<I')
            propertyValue = oStructTypedPropertyValue.GetBytes(length * 2)
            return True, type, propertyValue.decode('utf16').rstrip('\x00')
        elif type in dVTNumbers:
            return True, type, oStructTypedPropertyValue.Unpack(dVTNumbers[type])
        elif type == VT_BOOL:
            return True, type, 'False' if oStructTypedPropertyValue.Unpack('<h') == 0 else 'True'
        elif type == VT_FILETIME:
            return True, type, FILETIME2String(oStructTypedPropertyValue.Unpack('<Q'))
        elif type == VT_BLOB:
            blobSize = oStructTypedPropertyValue.Unpack('<I')
            blobData = oStructTypedPropertyValue.GetBytes(blobSize)
            extractedStrings = ExtractStrings(blobData)
            if extractedStrings == []:
                extractedMessage = ''
            else:
                extractedMessage = ' extracted strings: %s' % (b', '.join(extractedStrings)).decode()
            return True, type, ['BLOB size %d%s' % (blobSize, extractedMessage), blobData]
        elif type == VT_CF:
            return True, type, 'ClipboardData size %d type 0x%04x' % oStructTypedPropertyValue.Unpack('<II')
        elif type == (VT_VECTOR | VT_LPSTR):
            numberOfElements = oStructTypedPropertyValue.Unpack('<I')
            vector = []
            for iIter2 in range(numberOfElements):
                vector.append(oStructTypedPropertyValue.GetString('<I').decode('latin').rstrip('\x00'))
            return True, type, vector
        elif type & VT_VECTOR:
            numberOfElements = oStructTypedPropertyValue.Unpack('<I')
            vector = []
            for iIter2 in range(numberOfElements):
                identifiedV, typeV, propertyValueV = self.ParseTypedPropertyValue(oStructTypedPropertyValue)
                vector.append(propertyValueV)
            return True, type, vector
        else:
            return False, type, oCONSTANTS.Lookup(type, '<UNKNOWN>')

    def AnalyzePropertySet(self, propertySetNumner, guid, offset, options):
        self.result.append('PropertySet %d' % propertySetNumner)
        self.result.append('-------------')

        data = self.stream[offset:]
        oStruct = cStruct(data)
        size, numProperties = oStruct.Unpack('<II')
        dPropertyNames = {}
        if dGUIDs.get(guid, '<UNKNOWN>') == 'FMTID_SummaryInformation':
            self.attributeNames = olefile.OleMetadata.SUMMARY_ATTRIBS
        elif dGUIDs.get(guid, '<UNKNOWN>') == 'FMTID_DocSummaryInformation':
            self.attributeNames = olefile.OleMetadata.DOCSUM_ATTRIBS
        else:
            self.attributeNames = []
        self.result.append('Property Set GUID: %s (%s)' % (guid, dGUIDs.get(guid, '<UNKNOWN>')))
        self.result.append('Number of properties: %d' % numProperties)
        for iIter in range(numProperties):
            identifier, offset = oStruct.Unpack('<II')
            oStructTypedPropertyValue = cStruct(data[offset:])
            if identifier == DICTIONARY_PROPERTY_IDENTIFIER:
                numEntries = oStructTypedPropertyValue.Unpack('<I')
                keyNames = []
                for iIter2 in range(numEntries):
                    propertyIdentifier, length = oStructTypedPropertyValue.Unpack('<II')
                    propertyName = oStructTypedPropertyValue.GetBytes(length).decode('latin').rstrip('\x00')
                    dPropertyNames[propertyIdentifier] = propertyName
                    keyNames.append(propertyName)
                self.result.append(' Dictionary with %d entries: %s' % (numEntries, ', '.join(keyNames)))
            else:
                identified, type, propertyValue = self.ParseTypedPropertyValue(oStructTypedPropertyValue)
                attributeName = self.AttributeName(identifier, dPropertyNames)
                if identified:
                    extra = ''
                    if 'codepage' in attributeName.lower():
                        if propertyValue < 0:
                            propertyValue += 65536
                        extra = ' ' + dCodepages.get(propertyValue, '<UNKNOWN>')
                    if attributeName == 'version':
                        extra = ' 0x%08x' % propertyValue
                    if attributeName == 'dig_sig' and options.signature:
                        issuer, subject = ParseASN(propertyValue[1])
                        if issuer != None and subject != None:
                            self.result.append(' %s: issuer: %s subject: %s' % (attributeName, issuer, subject))
                        else:
                            self.result.append(' %s: %s%s' % (attributeName, propertyValue[0], extra))
                    else:
                        self.result.append(' %s: %s%s' % (attributeName, propertyValue, extra))
                else:
                    self.result.append(' %s: 0x%04x %s' % (attributeName, type, propertyValue))

    def Analyze(self):
        oParser = optparse.OptionParser()
        oParser.add_option('-s', '--signature', action='store_true', default=False, help='Parse signature')
        (options, args) = oParser.parse_args(self.options.split(' '))

        self.result = []

        oStruct = cStruct(self.stream)
        try:
            byteOrder, version = oStruct.Unpack('<HH')
        except Exception as e:
            if e.args[0] == 'Not enough data':
                return
            else:
                raise

        if byteOrder == 0xFFFE and version in [0, 1]:
            self.ran = True
            self.result.append('PropertySetStream version: %d' % version)
            headerPropertySetStream = oStruct.Unpack('<BBH16sI')
            self.result.append('PropertySetSystemIdentifier OSMajorVersion: %d OSMinorVersion: %d OSType: %d' % headerPropertySetStream[:3])
            self.result.append('PropertySetStream GUID: %s' % GUID2String(headerPropertySetStream[3]))
            headerPropertySet1 = oStruct.Unpack('<16sI')
            self.AnalyzePropertySet(1, GUID2String(headerPropertySet1[0]), headerPropertySet1[1], options)
            if headerPropertySetStream[4] == 2:
                headerPropertySet2 = oStruct.Unpack('<16sI')
                self.AnalyzePropertySet(2, GUID2String(headerPropertySet2[0]), headerPropertySet2[1], options)

        return self.result

AddPlugin(cMetadata)
