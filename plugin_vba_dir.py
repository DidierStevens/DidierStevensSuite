#!/usr/bin/env python

__description__ = 'VBA dir stream parser for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2023/04/23'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2023/04/23: start

Todo:
  write parser for REFERENCECONTROL
"""

#https://interoperability.blob.core.windows.net/files/MS-OVBA/%5bMS-OVBA%5d.pdf

def ParseREFERENCEREGISTERED(data):
    oStruct = cStruct(data)
    stringSize = oStruct.Unpack('<I')
    name = oStruct.GetBytes(stringSize).decode('latin')
    return name

def ParseREFERENCEPROJECT(data):
    oStruct = cStruct(data)
    stringSizeAbsolute = oStruct.Unpack('<I')
    nameAbsolute = oStruct.GetBytes(stringSizeAbsolute).decode('latin')
    stringSizeRelative = oStruct.Unpack('<I')
    nameRelative = oStruct.GetBytes(stringSizeRelative).decode('latin')
    majorVersion, minorVersion = oStruct.Unpack('<IH')
    return 'Fields = absolute: %s relative: %s majorversion: 0x%08x minorversion: 0x%08x' % (nameAbsolute, nameRelative, majorVersion, minorVersion)

def DisplayHexadecimal(data):
    return '0x' + binascii.b2a_hex(data).decode('latin')

def DisplayDecimal(data):
    return int.from_bytes(data, 'little')

def DisplayANSI(data):
    return data.decode('latin')

def DisplayUNICODE(data):
    return data.decode('utf16')

def MyRepr(data):
    if len(data) == 0:
        return ''
    else:
        return repr(data)

class cVBADir(cPluginParent):
    macroOnly = False
    name = 'VBA dir plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if self.streamname[-1].lower() == 'dir':

            PROJECTSYSKIND              = 0x0001
            PROJECTLCID                 = 0x0002
            PROJECTCODEPAGE             = 0x0003
            PROJECTNAME                 = 0x0004
            PROJECTDOCSTRING            = 0x0005
            PROJECTHELPFILEPATH         = 0x0006
            PROJECTHELPCONTEXT          = 0x0007
            PROJECTLIBFLAGS             = 0x0008
            PROJECTVERSION              = 0x0009
            PROJECTCONSTANTS            = 0x000C
            PROJECTMODULES              = 0x000F
            TERMINATOR                  = 0x0010
            PROJECTCOOKIE               = 0x0013
            PROJECTLCIDINVOKE           = 0x0014
            REFERENCENAME               = 0x0016
            MODULENAME                  = 0x0019
            MODULESTREAMNAME            = 0x001A
            MODULEDOCSTRING             = 0x001C
            MODULEHELPCONTEXT           = 0x001E
            REFERENCEREGISTERED         = 0x000D
            REFERENCEPROJECT            = 0x000E
            MODULETYPE_proc             = 0x0021
            MODULETYPE_doc_cls_dsgn     = 0x0022
            MODULEREADONLY              = 0x0025
            MODULEPRIVATE               = 0x0028
            MODULE_TERMINATOR           = 0x002B
            MODULECOOKIE                = 0x002C
            REFERENCECONTROL            = 0x002F
            MODULEOFFSET                = 0x0031
            MODULESTREAMNAME_UNICODE    = 0x0032
            REFERENCEORIGINAL           = 0x0033
            PROJECTCONSTANTS_UNICODE    = 0x003C
            PROJECTHELPFILEPATH_UNICODE = 0x003D
            REFERENCENAME_UNICODE       = 0x003E
            PROJECTDOCSTRING_UNICODE    = 0x0040
            MODULENAMEUNICODE           = 0x0047
            MODULEDOCSTRING_UNICODE     = 0x0048
            PROJECTCOMPATVERSION        = 0x004A

            dRecords = {
                PROJECTSYSKIND: 'PROJECTSYSKIND',
                PROJECTLCID: 'PROJECTLCID',
                PROJECTCODEPAGE: 'PROJECTCODEPAGE',
                PROJECTNAME: 'PROJECTNAME',
                PROJECTDOCSTRING: 'PROJECTDOCSTRING',
                PROJECTHELPFILEPATH: 'PROJECTHELPFILEPATH',
                PROJECTHELPCONTEXT: 'PROJECTHELPCONTEXT',
                PROJECTLIBFLAGS: 'PROJECTLIBFLAGS',
                PROJECTVERSION: 'PROJECTVERSION',
                PROJECTCONSTANTS: 'PROJECTCONSTANTS',
                PROJECTMODULES: 'PROJECTMODULES',
                TERMINATOR: 'TERMINATOR',
                PROJECTCOOKIE: 'PROJECTCOOKIE',
                PROJECTLCIDINVOKE: 'PROJECTLCIDINVOKE',
                REFERENCENAME: 'REFERENCENAME',
                MODULENAME: 'MODULENAME',
                MODULESTREAMNAME: 'MODULESTREAMNAME',
                REFERENCECONTROL: 'REFERENCECONTROL',
                MODULEOFFSET: 'MODULEOFFSET',
                MODULESTREAMNAME_UNICODE: 'MODULESTREAMNAME_UNICODE',
                REFERENCEORIGINAL: 'REFERENCEORIGINAL',
                REFERENCEREGISTERED: 'REFERENCEREGISTERED',
                REFERENCEPROJECT: 'REFERENCEPROJECT',
                MODULETYPE_proc: 'MODULETYPE_proc',
                MODULETYPE_doc_cls_dsgn: 'MODULETYPE_doc_cls_dsgn',
                PROJECTCONSTANTS_UNICODE: 'PROJECTCONSTANTS_UNICODE',
                PROJECTHELPFILEPATH_UNICODE: 'PROJECTHELPFILEPATH_UNICODE',
                REFERENCENAME_UNICODE: 'REFERENCENAME_UNICODE',
                PROJECTDOCSTRING_UNICODE: 'PROJECTDOCSTRING_UNICODE',
                PROJECTCOMPATVERSION: 'PROJECTCOMPATVERSION',
                MODULENAMEUNICODE: 'MODULENAMEUNICODE',
                MODULEDOCSTRING: 'MODULEDOCSTRING',
                MODULEDOCSTRING_UNICODE: 'MODULEDOCSTRING_UNICODE',
                MODULEHELPCONTEXT: 'MODULEHELPCONTEXT',
                MODULECOOKIE: 'MODULECOOKIE',
                MODULE_TERMINATOR: 'MODULE_TERMINATOR',
                MODULEREADONLY: 'MODULEREADONLY',
                MODULEPRIVATE: 'MODULEPRIVATE',
            }

            dRecordsDataType = {
                PROJECTSYSKIND: DisplayHexadecimal,
                PROJECTLCID: DisplayHexadecimal,
                PROJECTCODEPAGE: DisplayHexadecimal,
                PROJECTNAME: DisplayANSI,
                PROJECTDOCSTRING: DisplayANSI,
                PROJECTHELPFILEPATH: DisplayANSI,
                REFERENCEORIGINAL: DisplayANSI,
                PROJECTDOCSTRING_UNICODE: DisplayUNICODE,
                PROJECTHELPFILEPATH_UNICODE: DisplayUNICODE,
                REFERENCENAME: DisplayANSI,
                REFERENCENAME_UNICODE: DisplayUNICODE,
                REFERENCEREGISTERED: ParseREFERENCEREGISTERED,
                REFERENCEPROJECT: ParseREFERENCEPROJECT,
                MODULENAME: DisplayANSI,
                MODULENAMEUNICODE: DisplayUNICODE,
                PROJECTMODULES: DisplayDecimal,
                PROJECTCOOKIE: DisplayHexadecimal,
                PROJECTLCIDINVOKE: DisplayHexadecimal,
                PROJECTHELPCONTEXT: DisplayHexadecimal,
                PROJECTLIBFLAGS: DisplayHexadecimal,
                PROJECTVERSION: DisplayHexadecimal,
                MODULESTREAMNAME: DisplayANSI,
                MODULESTREAMNAME_UNICODE: DisplayUNICODE,
                MODULEDOCSTRING: DisplayANSI,
                MODULEDOCSTRING_UNICODE: DisplayUNICODE,
                MODULEOFFSET: DisplayDecimal,
                MODULEHELPCONTEXT: DisplayHexadecimal,
                MODULECOOKIE: DisplayHexadecimal,
                PROJECTCONSTANTS: DisplayANSI,
                PROJECTCONSTANTS_UNICODE: DisplayUNICODE,
            }

            data = Decompress(self.stream, False)
            if data[0]:
                oStruct = cStruct(data[1].encode('latin'))
                while True:
                    recordType, recordSize = oStruct.Unpack('<HI')
                    if recordType == PROJECTVERSION:
                        recordSize = 6
                    data = oStruct.GetBytes(recordSize)
                    dataParsed = dRecordsDataType.get(recordType, MyRepr)(data)
                    result.append('0x%04x %04d %-27s %s' % (recordType, recordSize, dRecords.get(recordType, '<UNKNOWN>'), dataParsed))
                    if recordType == TERMINATOR:
                        break
                remainder = oStruct.GetBytes()
                if remainder != b'':
                    result.append('Warning: remainder = %s' % repr(remainder))
            else:
                result.append('Decompression error')

            self.ran = True

        return result

AddPlugin(cVBADir)
