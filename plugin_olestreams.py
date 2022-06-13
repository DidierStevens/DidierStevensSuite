#!/usr/bin/env python

__description__ = 'OLE streams plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2022/06/13'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/06/06: start
  2022/06/06: 0.0.2 continue
  2022/06/08: continue
  2022/06/13: continue

Todo:
"""

duriFlags = {
    'A': 'createAllowRelative (1 bit): A bit that specifies that if the URI scheme is unspecified and not implicitly "file," a relative scheme is assumed during creation of the URI.',
    'B': 'createAllowImplicitWildcardScheme (1 bit): A bit that specifies that if the URI scheme is unspecified and not implicitly "file," a wildcard scheme is assumed during creation of the URI.',
    'C': 'createAllowImplicitFileScheme (1 bit): A bit that specifies that if the URI scheme is unspecified and the URI begins with a drive letter or a UNC path, a file scheme is assumed during creation of the URI.',
    'D': 'createNoFrag (1 bit): A bit that specifies that if a URI query string is present, the URI fragment is not looked for during creation of the URI.',
    'E': 'createNoCanonicalize (1 bit): A bit that specifies that the scheme, host, authority, path, and fragment will not be canonicalized during creation of the URI. This value MUST be 0 if createCanonicalize equals 1.',
    'F': 'createCanonicalize (1 bit): A bit that specifies that the scheme, host, authority, path, and fragment will be canonicalized during creation of the URI. This value MUST be 0 if createNoCanonicalize equals 1.',
    'G': 'createFileUseDosPath (1 bit): A bit that specifies that MS-DOS path compatibility mode will be used during creation of file URIs.',
    'H': 'createDecodeExtraInfo (1 bit): A bit that specifies that percent encoding and percent decoding canonicalizations will be performed on the URI query and URI fragment during creation of the URI. This field takes precedence over the createNoCanonicalize field. This value MUST be 0 if createNoDecodeExtraInfo equals 1. The value 1 can also be saved. This will cause a return value of E_INVALIDARG from CreateUri().',
    'I': 'createNoDecodeExtraInfo (1 bit): A bit that specifies that percent encoding and percent decoding canonicalizations will not be performed on the URI query and URI fragment during creation of the URI. This field takes precedence over the createCanonicalize field. This value MUST be 0 if createDecodeExtraInfo equals 1. The value 1 can also be saved. This will cause a return value of E_INVALIDARG from CreateUri().',
    'J': 'createCrackUnknownSchemes (1 bit): A bit that specifies that hierarchical URIs with unrecognized URI schemes will be treated like hierarchical URIs during creation of the URI. This value MUST be 0 if createNoCrackUnknownSchemes equals 1.',
    'K': 'createNoCrackUnknownSchemes (1 bit): A bit that specifies that hierarchical URIs with unrecognized URI schemes will be treated like opaque URIs during creation of the URI. This value MUST be 0 if createCrackUnknownSchemes equals 1.',
    'L': 'createPreProcessHtmlUri (1 bit): A bit that specifies that preprocessing will be performed on the URI to remove control characters and white space during creation of the URI. This value MUST be 0 if createNoPreProcessHtmlUri equals 1.',
    'M': 'createNoPreProcessHtmlUri (1 bit): A bit that specifies that preprocessing will not be performed on the URI to remove control characters and white space during creation of the URI. This value MUST be 0 if createPreProcessHtmlUri equals 1.',
    'N': 'createIESettings (1 bit): A bit that specifies that registry settings will be used to determine default URL parsing behavior during creation of the URI. This value MUST be 0 if createNoIESettings equals 1.',
    'O': 'createNoIESettings (1 bit): A bit that specifies that registry settings will not be used to determine default URL parsing behavior during creation of the URI. This value MUST be 0 if createIESettings equals 1.',
    'P': 'createNoEncodeForbiddenCharacters (1 bit): A bit that specifies that URI characters forbidden in [RFC3986] will not be percent-encoded during creation of the URI.',
}

def GUIDToBytes(clsid):
    parts = [binascii.a2b_hex(part) for part in clsid.split('-')]
    return parts[0][::-1] + parts[1][::-1] + parts[2][::-1] + parts[3] + parts[4]

def BytesToGUID(data):
    return '{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}' % tuple(data[3::-1] + data[5:3:-1] + data[7:5:-1] + data[8:16])


def Unpack(format, data):
    size = struct.calcsize(format)
    if size > len(data):
        return []
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

def UnpackCounterBytes(format, data):
    size = struct.calcsize(format)
    if size > len(data):
        return []
    length = struct.unpack(format, data[:size])[0]
    data = data[size:]
    if length == 0:
        result = [b'']
    elif length > len(data):
        return []
    else:
        result = [data[:length]]

    result.append(data[length:])
    return result

def UnpackCounterBytes2(format, data):
    size = struct.calcsize(format)
    if size > len(data):
        return []
    length = struct.unpack(format, data[:size])[0] * 2
    data = data[size:]
    if length == 0:
        result = [b'']
    elif length > len(data):
        return []
    else:
        result = [data[:length]]

    result.append(data[length:])
    return result

def UnpackStream(format, data):
    size = struct.calcsize(format)
    if size > len(data):
        return []
    length = struct.unpack(format, data[:size])[0]
    data = data[size:]
    if length == 0:
        result = [b'']
    else:
        length -= size
        if length > len(data):
            return []
        else:
            result = [data[:length]]

    result.append(data[length:])
    return result

def UnpackBytes(size, data):
    if size > len(data):
        return []
    return [data[:size], data[size:]]

def UnpackNULLTerminatedUNICODEString(data):
    string = b''
    while len(data) >= 2 and data[:2] != b'\x00\x00':
        string += data[:2]
        data = data[2:]
    return [string.decode('utf16'), data[2:]]

def Indent(indentation, list):
    return [indentation + item for item in list]

def InterpretBits(value, dBits, falseToo=False):
    result = []

    for key in dBits.keys():
        if isinstance(key, str):
            position = ord(key) - ord('A')
        else:
            position = key
        position = 2 ** position
        if value & position == position:
            result.append('1: %s %s' % (key, dBits[key]))
        elif falseToo:
            result.append('0: %s %s' % (key, dBits[key]))

    return result

#https://docs.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-createitemmoniker
def ParseItemMonikerStream(data):
    returnvalue = UnpackCounterBytes('<I', data)
    if returnvalue == []:
        return []
    delimiter, data = returnvalue
    returnvalue = UnpackCounterBytes('<I', data)
    if returnvalue == []:
        return []
    item, data = returnvalue
    if returnvalue == []:
        return []
    result = [delimiter.decode('utf16'), item.decode('latin').rstrip('\x00'), data]
    return result

#URLMoniker 2.3.7.6 https://interoperability.blob.core.windows.net/files/MS-OSHARED/%5bMS-OSHARED%5d.pdf
def ParseURLMonikerStream(data):
    returnvalue = Unpack('<I', data)
    if returnvalue == []:
        return []
    length, data = returnvalue
    dataURLMoniker = data[:length]
    returnvalue = UnpackNULLTerminatedUNICODEString(dataURLMoniker)
    if returnvalue == []:
        url = '<ERROR>'
        remainder = b''
    else:
        url, remainder = returnvalue

    returnvalue = UnpackBytes(16, remainder)
    if returnvalue == []:
        clsid = '<ERROR>'
        remainder = b''
    else:
        clsid, remainder = returnvalue
        clsid = BytesToGUID(clsid)

    returnvalue = Unpack('<I', remainder)
    if returnvalue == []:
        version = '<ERROR>'
        remainder = b''
    else:
        version, remainder = returnvalue

    returnvalue = Unpack('<I', remainder)
    if returnvalue == []:
        uriFlags = '<ERROR>'
        remainder = b''
    else:
        uriFlags, remainder = returnvalue

    return [url, clsid, version, uriFlags, data[length:]]

#https://interoperability.blob.core.windows.net/files/MS-OSHARED/%5bMS-OSHARED%5d.pdf
def ParseCompositeMonikerStream(data):
    returnvalue = Unpack('<I', data)
    if returnvalue == []:
        return []
    counter, data = returnvalue

    monikerResults = []
    while len(data) > 0:
        if len(data) < 16:
            return []
        clsid = BytesToGUID(data[:16])
        data = data[16:]
        description = 'clsid: %s (%s)' % (clsid, LookupClsID(clsid))
        if clsid == '{79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}':
            returnvalue = ParseURLMonikerStream(data)
            if returnvalue == []:
                return []
            if returnvalue[1] == '{F4815879-1D3B-487F-AF2C-825DC4852763}':
                serialGUIDExpected = ' (expected value)'
            else:
                serialGUIDExpected = ' (different from expected value {F4815879-1D3B-487F-AF2C-825DC4852763})'
            result = [description, 'URL: %s' % returnvalue[0], 'SerialGUID: %s%s' % (returnvalue[1], serialGUIDExpected), 'Version: %s' % returnvalue[2], 'uriFlags: %s' % returnvalue[3]]
            if isinstance(returnvalue[3], int):
                result.extend(Indent('  ', InterpretBits(returnvalue[3], duriFlags)))
            monikerResults.append(result)
            data = returnvalue[4]
        elif clsid == '{00000304-0000-0000-C000-000000000046}':
            returnvalue = ParseItemMonikerStream(data)
            if returnvalue == []:
                return []
            result = [description, 'Delimiter: %s' % returnvalue[0], 'Item: %s' % returnvalue[1]]
            monikerResults.append(result)
            data = returnvalue[2]
        else:
            raise

    result = [counter, monikerResults, data]
    return result

def ParseMonikerStream(data):
    result = []
    if len(data) < 16:
        return []
    clsid = BytesToGUID(data[:16])
    data = data[16:]
    if clsid == '{00000304-0000-0000-C000-000000000046}':
        returnvalue = ParseItemMonikerStream(data)
        if returnvalue != []:
            result = ['Delimiter: %s' % returnvalue[0], 'Item: %s' % returnvalue[1]]
            data = returnvalue[2]
    elif clsid == '{00000309-0000-0000-C000-000000000046}':
        returnvalue = ParseCompositeMonikerStream(data)
        if returnvalue != []:
            result = ['Counter: %d' % returnvalue[0]]
            for items in returnvalue[1]:
                result.append('  ' + items[0])
                result.extend(Indent('    ', items[1:]))
            data = returnvalue[2]
    elif clsid == '{79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}':
        returnvalue = ParseURLMonikerStream(data)
        if returnvalue != []:
            result = ['URL: %s' % returnvalue[0], 'SerialGUID: %s' % returnvalue[1], 'Version: %s' % returnvalue[2], 'uriFlags: %s' % returnvalue[3]]
            if isinstance(returnvalue[3], int):
                result.extend(Indent('  ', InterpretBits(returnvalue[3], duriFlags)))
            data = returnvalue[4]
    return [clsid, result, data]

def LookupClsID(clsid):
    clsidNormalized = clsid.strip('{').strip('}').upper()
    return KNOWN_CLSIDS.get(clsidNormalized, '<UNKNOWN>')

def FindCLSIDs(data):
    result = []
    if KNOWN_CLSIDS == {}:
        result.append('<oletools missing>')
    for clsid, desc in KNOWN_CLSIDS.items():
        for position in FindAll(data, GUIDToBytes(clsid)):
            result.append('0x%08x %s %s' % (position, clsid, desc))

    return sorted(result)

def UnpackClipboardFormatOrString(data):
    returnvalue = Unpack('<I', data)
    if returnvalue == []:
        return []
    markerOrLength, dataRemainder = returnvalue
    if markerOrLength == 0:
        return [markerOrLength, None, dataRemainder]
    if markerOrLength in [0xFFFFFFFE, 0xFFFFFFFF]:
        returnvalue = Unpack('<I', dataRemainder)
        if returnvalue == []:
            return []
        clipboardFormat, dataRemainder = returnvalue
        return [markerOrLength, clipboardFormat, dataRemainder]
    else:
        returnvalue = UnpackBytes(markerOrLength, dataRemainder)
        if returnvalue == []:
            return []
        ansiString, dataRemainder = returnvalue
        return [markerOrLength, ansiString, dataRemainder]

class cCLSID(cPluginParent):
    macroOnly = False
    name = 'OLE streams plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze1Ole(self):
        result = []

        returnvalue = Unpack('<I', self.stream)
        if returnvalue == []:
            return result
        version, streamRemainder = returnvalue
        result.append('Version: %04x' % version)

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        flags, streamRemainder = returnvalue
        result.append('Flags: %s' % bin(flags))
        if 0x01 & flags == 0x01:
            result.append('  Linked object')
        else:
            result.append('  Embedded object')
        if 0x08 & flags == 0x08:
            result.append('  Implementation specific bit set')

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        linkUpdateOption, streamRemainder = returnvalue
        result.append('LinkUpdateOption: %04x' % linkUpdateOption)

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        reserved1, streamRemainder = returnvalue
        result.append('Reserved1: %04x' % reserved1)

        returnvalue = UnpackStream('<I', streamRemainder)
        if returnvalue == []:
            return result
        reservedMonikerStream, streamRemainder = returnvalue
        if len(reservedMonikerStream) > 0:
            result.append('ReservedMonikerStream present')
            returnvalue = ParseMonikerStream(reservedMonikerStream)
            if returnvalue == []:
                return result
            clsidMonikerstream, resultMoniker, remainderMoniker = returnvalue
            result.append('  clsid: %s (%s)' % (clsidMonikerstream, LookupClsID(clsidMonikerstream)))
            result.extend(Indent('  ', resultMoniker))
            if len(remainderMoniker) > 0:
                result.append('  extra bytes: %d' % len(remainderMoniker))
        else:
            result.append('ReservedMonikerStream not present')

        returnvalue = UnpackStream('<I', streamRemainder)
        if returnvalue == []:
            return result
        relativeSourceMonikerStream, streamRemainder = returnvalue
        if len(relativeSourceMonikerStream) > 0:
            result.append('RelativeSourceMonikerStream present')
            returnvalue = ParseMonikerStream(relativeSourceMonikerStream)
            if returnvalue == []:
                return result
            clsidMonikerstream, resultMoniker, remainderMoniker = returnvalue
            result.append('  clsid: %s (%s)' % (clsidMonikerstream, LookupClsID(clsidMonikerstream)))
            result.extend(Indent('  ', resultMoniker))
            if len(remainderMoniker) > 0:
                result.append('  extra bytes: %d' % len(remainderMoniker))
        else:
            result.append('RelativeSourceMonikerStream not present')

        returnvalue = UnpackStream('<I', streamRemainder)
        if returnvalue == []:
            return result
        absoluteSourceMonikerStream, streamRemainder = returnvalue
        if len(absoluteSourceMonikerStream) > 0:
            result.append('AbsoluteSourceMonikerStream present')
            returnvalue = ParseMonikerStream(absoluteSourceMonikerStream)
            if returnvalue == []:
                return result
            clsidMonikerstream, resultMoniker, remainderMoniker = returnvalue
            result.append('  clsid: %s (%s)' % (clsidMonikerstream, LookupClsID(clsidMonikerstream)))
            result.extend(Indent('  ', resultMoniker))
            if len(remainderMoniker) > 0:
                result.append('  extra bytes: %d' % len(remainderMoniker))
                result.append(repr(remainderMoniker))
        else:
            result.append('AbsoluteSourceMonikerStream not present')

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        clsidIndicator, streamRemainder = returnvalue
        result.append('ClsidIndicator: %04x' % clsidIndicator)

        returnvalue = UnpackBytes(16, streamRemainder)
        if returnvalue == []:
            return result
        clsid, streamRemainder = returnvalue
        result.append('Clsid: %s' % BytesToGUID(clsid))

        returnvalue = UnpackCounterBytes('<I', streamRemainder)
        if returnvalue == []:
            return result
        reservedDisplayName, streamRemainder = returnvalue
        result.append('ReservedDisplayName: %s' % reservedDisplayName.decode('utf16').rstrip('\x00'))

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        reserved2, streamRemainder = returnvalue
        result.append('Reserved2: %08x' % reserved2)

        returnvalue = Unpack('<Q', streamRemainder)
        if returnvalue == []:
            return result
        localUpdateTime, streamRemainder = returnvalue
        result.append('LocalUpdateTime: %016x' % localUpdateTime)

        returnvalue = Unpack('<Q', streamRemainder)
        if returnvalue == []:
            return result
        localCheckUpdateTime, streamRemainder = returnvalue
        result.append('LocalCheckUpdateTime: %016x' % localCheckUpdateTime)

        returnvalue = Unpack('<Q', streamRemainder)
        if returnvalue == []:
            return result
        remoteUpdateTime, streamRemainder = returnvalue
        result.append('RemoteUpdateTime: %016x' % remoteUpdateTime)

        if len(streamRemainder) > 0:
            result.append('extra bytes: %d' % len(streamRemainder))

        return result

    #have yet to find documentation for \003LinkInfo
    def Analyze3LinkInfo(self):
        result = []

        returnvalue = UnpackCounterBytes('<H', self.stream)
        if returnvalue == []:
            return result
        urlansi, streamRemainder = returnvalue
        result.append('URL(ansi): %s' % urlansi.decode('latin'))

        returnvalue = UnpackCounterBytes('<H', streamRemainder)
        if returnvalue == []:
            return result
        itemansi, streamRemainder = returnvalue
        result.append('Item(ansi): %s' % itemansi.decode('latin'))

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        unknown, streamRemainder = returnvalue
        result.append('Unknown: %08x' % unknown)

        returnvalue = UnpackCounterBytes2('<H', streamRemainder)
        if returnvalue == []:
            return result
        urlunicode, streamRemainder = returnvalue
        result.append('URL(unicode): %s' % urlunicode.decode('utf16'))

        returnvalue = UnpackCounterBytes2('<H', streamRemainder)
        if returnvalue == []:
            return result
        itemunicode, streamRemainder = returnvalue
        result.append('Item(unicode): %s' % itemunicode.decode('utf16'))

        if len(streamRemainder) > 0:
            result.append('extra bytes: %d' % len(streamRemainder))

        return result

    #https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/13ba10a8-d8b2-433b-bf3b-ec238dc8f9ce
    def Analyze3ObjInfo(self):
        result = []
        dCF = {
            0x0001: 'Rich Text Format',
            0x0002: 'Text format',
            0x0003: 'Metafile or Enhanced Metafile, depending on ODTPersist2.fStoredAsEMF',
            0x0004: 'Bitmap',
            0x0005: 'Device Independent Bitmap',
            0x000A: 'HTML format',
            0x0014: 'Unicode text format',
        }
        dODTPersist1 = {
            'A': 'reserved1 (1 bit): Undefined and MUST be ignored.',
            'B': 'fDefHandler (1 bit): If this bit is 1, then the application MUST assume that this OLE object’s class identifier (CLSID) is {00020907-0000-0000-C000-000000000046}.',
            'C': 'reserved2 (1 bit): Undefined and MUST be ignored.',
            'D': 'reserved3 (1 bit): Undefined and MUST be ignored.',
            'E': 'fLink (1 bit): A bit that specifies whether this OLE object is a link.',
            'F': 'reserved4 (1 bit): Undefined and MUST be ignored.',
            'G': 'fIcon (1 bit): A bit that specifies whether this OLE object is being represented by an icon.',
            'H': 'fIsOle1 (1 bit): A bit that specifies whether this OLE object is only compatible with OLE 1. If this bit is zero, then the object is compatible with OLE 2.',
            'I': 'fManual (1 bit): A bit that specifies whether the user has requested that this OLE object only be updated in response to a user action. If fManual is zero, then the user has requested that this OLE object update automatically. If fLink is zero, then fManual is undefined and MUST be ignored.',
            'J': 'fRecomposeOnResize (1 bit): A bit that specifies whether this OLE object has requested to be notified when it is resized by its container.',
            'K': 'reserved5 (1 bit): MUST be zero and MUST be ignored.',
            'L': 'reserved6 (1 bit): MUST be zero and MUST be ignored.',
            'M': 'fOCX (1 bit): A bit that specifies whether this object is an OLE control.',
            'N': 'fStream (1 bit): If fOCX is zero, then this bit MUST be zero. If fOCX is 1, then fStream is a bit that specifies whether this OLE control stores its data in a single stream instead of a storage. If fStream is 1, then the data for the OLE control is in a stream called "\003OCXDATA" where \003 is the character with value 0x0003, not the string literal "\003".',
            'O': 'reserved7 (1 bit): Undefined and MUST be ignored.',
            'P': 'fViewObject (1 bit): A bit that specifies whether this OLE object supports the IViewObject interface as described in [MSDOCS-IViewObject].',
        }
        dODTPersist2 = {
            'A': 'fEMF (1 bit): A bit that specifies that the presentation of this OLE object in the document is in the Enhanced Metafile format. This is different from fStoredAsEMF in the case of an object being represented as an icon. For icons, the icon can be an Enhanced Metafile even if the OLE object does not support the Enhanced Metafile format.',
            'B': 'reserved1 (1 bit): MUST be zero and MUST be ignored.',
            'C': 'fQueriedEMF (1 bit): A bit that specifies whether the application that saved this Word Binary file had queried this OLE object to determine whether it supported the Enhanced Metafile format.',
            'D': 'fStoredAsEMF (1 bit): A bit that specifies that this OLE object supports the Enhanced Metafile format.',
            'E': 'reserved2 (1 bit): Undefined and MUST be ignored.',
            'F': 'reserved3 (1 bit): Undefined and MUST be ignored.',
        }

        returnvalue = Unpack('<H', self.stream)
        if returnvalue == []:
            return result
        odtpersist1, streamRemainder = returnvalue
        result.append('odtpersist1: %s' % bin(odtpersist1))
        result.extend(Indent('  ', InterpretBits(odtpersist1, dODTPersist1)))

        returnvalue = Unpack('<H', streamRemainder)
        if returnvalue == []:
            return result
        cf, streamRemainder = returnvalue
        result.append('cf: %d (%s)' % (cf, dCF.get(cf, '<UNKNOWN>')))

        returnvalue = Unpack('<H', streamRemainder)
        if returnvalue == []:
            return result
        odtpersist2, streamRemainder = returnvalue
        result.append('odtpersist2: %s' % bin(odtpersist2))
        result.extend(Indent('  ', InterpretBits(odtpersist2, dODTPersist2)))

        if len(streamRemainder) > 0:
            result.append('extra bytes: %d' % len(streamRemainder))

        return result

    def Analyze1CompObj(self):
        result = []

        returnvalue = Unpack('<I', self.stream)
        if returnvalue == []:
            return result
        reserved1, streamRemainder = returnvalue
        result.append('Reserved1: %08x' % reserved1)

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        version, streamRemainder = returnvalue
        result.append('Version: %08x' % version)

        returnvalue = UnpackBytes(20, streamRemainder)
        if returnvalue == []:
            return result
        reserved2, streamRemainder = returnvalue
        result.append('Reserved2')
        resultCLSIDs = FindCLSIDs(reserved2)
        if len(resultCLSIDs) > 0:
            result.append('  Contains known CLSIDs:')
            result.extend(Indent('    ', resultCLSIDs))

        returnvalue = UnpackCounterBytes('<I', streamRemainder)
        if returnvalue == []:
            return result
        ansiUserType, streamRemainder = returnvalue
        result.append('AnsiUserType: %s' % ansiUserType.decode('latin').rstrip('\x00'))

        returnvalue = UnpackClipboardFormatOrString(streamRemainder)
        if returnvalue == []:
            return result
        temp1, temp2, streamRemainder = returnvalue
        if temp1 == 0:
            result.append('ClipboardFormatOrAnsiString not present')
        elif temp1 in [0xFFFFFFFE, 0xFFFFFFFF]:
            result.append('ClipboardFormatOrAnsiString: %08x' % temp2)
        else:
            result.append('ClipboardFormatOrAnsiString: %s' % temp2.decode('latin').rstrip('\x00'))

        returnvalue = Unpack('<I', streamRemainder)
        if returnvalue == []:
            return result
        reserved1, streamRemainder = returnvalue
        if reserved1 == 0 or reserved1 > 0x28:
            result.append('Reserved1: 0x%08x (ignoring remainder)' % reserved1)
        else:
            returnvalue = UnpackBytes(reserved1, streamRemainder)
            if returnvalue == []:
                return result
            stringAnsi, streamRemainder = returnvalue
            result.append('Reserved1: %s' % stringAnsi.decode('latin').rstrip('\x00'))

            returnvalue = Unpack('<I', streamRemainder)
            if returnvalue == []:
                return result
            unicodeMarker, streamRemainder = returnvalue
            result.append('UnicodeMarker: 0x%08x' % unicodeMarker)
            if unicodeMarker == 0x71B239F4:
                returnvalue = UnpackCounterBytes('<I', streamRemainder)
                if returnvalue == []:
                    return result
                unicodeUserType, streamRemainder = returnvalue
                result.append('UnicodeUserType: %s' % unicodeUserType.decode('utf16').rstrip('\x00'))

                returnvalue = UnpackClipboardFormatOrString(streamRemainder)
                if returnvalue == []:
                    return result
                temp1, temp2, streamRemainder = returnvalue
                if temp1 == 0:
                    result.append('ClipboardFormatOrUnicodeString not present')
                elif temp1 in [0xFFFFFFFE, 0xFFFFFFFF]:
                    result.append('ClipboardFormatOrUnicodeString: %08x' % temp2)
                else:
                    result.append('ClipboardFormatOrUnicodeString: %s' % temp2.decode('utf16').rstrip('\x00'))

                returnvalue = UnpackCounterBytes('<I', streamRemainder)
                if returnvalue == []:
                    return result
                reserved2, streamRemainder = returnvalue
                result.append('Reserved2: %s' % reserved2.decode('utf16').rstrip('\x00'))

        if len(streamRemainder) > 0:
            result.append('extra bytes: %d' % len(streamRemainder))
            result.append('  %s' % repr(streamRemainder))

        return result

    def Analyze(self):
        result = []
        self.ran = True
        stream = self.stream

        if self.streamname[-1] == '\x01Ole':
            result = self.Analyze1Ole()
        elif self.streamname[-1] == '\x03LinkInfo':
            result = self.Analyze3LinkInfo()
        elif self.streamname[-1] == '\x03ObjInfo':
            result = self.Analyze3ObjInfo()
        elif self.streamname[-1] == '\x01CompObj':
            result = self.Analyze1CompObj()
        else:
            if KNOWN_CLSIDS == {}:
                result.append('<oletools missing>')
            for clsid, desc in KNOWN_CLSIDS.items():
                for position in FindAll(stream, GUIDToBytes(clsid)):
                    result.append('0x%08x %s %s' % (position, clsid, desc))

            return sorted(result)

        return result

AddPlugin(cCLSID)
