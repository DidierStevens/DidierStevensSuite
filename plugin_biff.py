#!/usr/bin/env python

__description__ = 'BIFF plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.3'
__date__ = '2018/10/26'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/11/15: start
  2014/11/21: changed interface: added options; added options -a (asciidump) and -s (strings)
  2017/12/10: 0.0.2 added optparse & option -o
  2017/12/12: added option -f
  2017/12/13: added 0x support for option -f
  2018/10/24: 0.0.3 started coding Excel 4.0 macro support
  2018/10/25: continue
  2018/10/26: continue

Todo:
"""

import struct
import re
import optparse

def CombineHexASCII(hexDump, asciiDump, length):
    if hexDump == '':
        return ''
    return hexDump + '  ' + (' ' * (3 * (length - len(asciiDump)))) + asciiDump

def HexASCII(data, length=16):
    result = []
    if len(data) > 0:
        hexDump = ''
        asciiDump = ''
        for i, b in enumerate(data):
            if i % length == 0:
                if hexDump != '':
                    result.append(CombineHexASCII(hexDump, asciiDump, length))
                hexDump = '%08X:' % i
                asciiDump = ''
            hexDump += ' %02X' % ord(b)
            asciiDump += IFF(ord(b) >= 32, b, '.')
        result.append(CombineHexASCII(hexDump, asciiDump, length))
    return result

def StringsASCII(data):
    return re.findall('[^\x00-\x08\x0A-\x1F\x7F-\xFF]{4,}', data)

def StringsUNICODE(data):
    return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall('(([^\x00-\x08\x0A-\x1F\x7F-\xFF]\x00){4,})', data)]

def Strings(data, encodings='sL'):
    dStrings = {}
    for encoding in encodings:
        if encoding == 's':
            dStrings[encoding] = StringsASCII(data)
        elif encoding == 'L':
            dStrings[encoding] = StringsUNICODE(data)
    return dStrings

def ParseExpression(expression):
    dTokens = {
0x01: 'ptgExp',
0x02: 'ptgTbl',
0x03: 'ptgAdd',
0x04: 'ptgSub',
0x05: 'ptgMul',
0x06: 'ptgDiv',
0x07: 'ptgPower',
0x08: 'ptgConcat',
0x09: 'ptgLT',
0x0A: 'ptgLE',
0x0B: 'ptgEQ',
0x0C: 'ptgGE',
0x0D: 'ptgGT',
0x0E: 'ptgNE',
0x0F: 'ptgIsect',
0x10: 'ptgUnion',
0x11: 'ptgRange',
0x12: 'ptgUplus',
0x13: 'ptgUminus',
0x14: 'ptgPercent',
0x15: 'ptgParen',
0x16: 'ptgMissArg',
0x17: 'ptgStr',
0x19: 'ptgAttr',
0x1A: 'ptgSheet',
0x1B: 'ptgEndSheet',
0x1C: 'ptgErr',
0x1D: 'ptgBool',
0x1E: 'ptgInt',
0x1F: 'ptgNum',
0x20: 'ptgArray',
0x21: 'ptgFunc',
0x22: 'ptgFuncVar',
0x23: 'ptgName',
0x24: 'ptgRef',
0x25: 'ptgArea',
0x26: 'ptgMemArea',
0x27: 'ptgMemErr',
0x28: 'ptgMemNoMem',
0x29: 'ptgMemFunc',
0x2A: 'ptgRefErr',
0x2B: 'ptgAreaErr',
0x2C: 'ptgRefN',
0x2D: 'ptgAreaN',
0x2E: 'ptgMemAreaN',
0x2F: 'ptgMemNoMemN',
0x39: 'ptgNameX',
0x3A: 'ptgRef3d',
0x3B: 'ptgArea3d',
0x3C: 'ptgRefErr3d',
0x3D: 'ptgAreaErr3d',
0x40: 'ptgArrayV',
0x41: 'ptgFuncV',
0x42: 'ptgFuncVarV',
0x43: 'ptgNameV',
0x44: 'ptgRefV',
0x45: 'ptgAreaV',
0x46: 'ptgMemAreaV',
0x47: 'ptgMemErrV',
0x48: 'ptgMemNoMemV',
0x49: 'ptgMemFuncV',
0x4A: 'ptgRefErrV',
0x4B: 'ptgAreaErrV',
0x4C: 'ptgRefNV',
0x4D: 'ptgAreaNV',
0x4E: 'ptgMemAreaNV',
0x4F: 'ptgMemNoMemNV',
0x58: 'ptgFuncCEV',
0x59: 'ptgNameXV',
0x5A: 'ptgRef3dV',
0x5B: 'ptgArea3dV',
0x5C: 'ptgRefErr3dV',
0x5D: 'ptgAreaErr3dV',
0x60: 'ptgArrayA',
0x61: 'ptgFuncA',
0x62: 'ptgFuncVarA',
0x63: 'ptgNameA',
0x64: 'ptgRefA',
0x65: 'ptgAreaA',
0x66: 'ptgMemAreaA',
0x67: 'ptgMemErrA',
0x68: 'ptgMemNoMemA',
0x69: 'ptgMemFuncA',
0x6A: 'ptgRefErrA',
0x6B: 'ptgAreaErrA',
0x6C: 'ptgRefNA',
0x6D: 'ptgAreaNA',
0x6E: 'ptgMemAreaNA',
0x6F: 'ptgMemNoMemNA',
0x78: 'ptgFuncCEA',
0x79: 'ptgNameXA',
0x7A: 'ptgRef3dA',
0x7B: 'ptgArea3dA',
0x7C: 'ptgRefErr3dA',
0x7D: 'ptgAreaErr3dA',
}

    dFunctions = {0x36: 'HALT', 0x6E: 'EXEC', 0x76: 'ALERT', 0x95: 'REGISTER', 0xAC: 'WHILE', 0xAE: 'NEXT'}
    result = ''
    while len(expression) > 0:
        ptgid = ord(expression[0])
        expression = expression[1:]
        if ptgid in dTokens:
            result += dTokens[ptgid] + ' '
            if ptgid == 0x17:
                length = ord(expression[0])
                expression = expression[1:]
                if expression[0] == '\x00': # probably BIFF8 -> UNICODE (compressed)
                    expression = expression[1:]
                result += '"%s" ' % expression[:length]
                expression = expression[length:]
            elif ptgid == 0x19:
                grbit = ord(expression[0])
                expression = expression[1:]
                if grbit & 0x04:
                    result += 'CHOOSE '
                    break
                else:
                    expression = expression[2:]
            elif ptgid == 0x16 or ptgid == 0x0e:
                pass
            elif ptgid == 0x1e:
                result += '%d ' % (ord(expression[0]) + ord(expression[1]) * 0x100)
                expression = expression[2:]
            elif ptgid == 0x41:
                functionid = ord(expression[0]) + ord(expression[1]) * 0x100
                result += '%04x (%s) ' % (functionid, dFunctions.get(functionid % 0x8000, '???'))
                expression = expression[2:]
            elif ptgid == 0x22 or ptgid == 0x42:
                functionid = ord(expression[1]) + ord(expression[2]) * 0x100
                result += 'args %d func %04x (%s) ' % (ord(expression[0]), functionid, dFunctions.get(functionid % 0x8000, '???'))
                expression = expression[3:]
            elif ptgid == 0x23:
                result += '%04x ' % (ord(expression[0]) + ord(expression[1]) * 0x100)
                expression = expression[14:]
            elif ptgid == 0x1f:
                result += 'FLOAT '
                expression = expression[8:]
            elif ptgid == 0x26:
                expression = expression[4:]
                expression = expression[ord(expression[0]) + ord(expression[1]) * 0x100:]
                result += 'REFERENCE-EXPRESSION '
            elif ptgid == 0x01:
                formatcodes = 'HH'
                formatsize = struct.calcsize(formatcodes)
                row, column = struct.unpack(formatcodes, expression[0:formatsize])
                expression = expression[formatsize:]
                result += 'R%dC%d ' % (row + 1, column + 1)
            elif ptgid == 0x24 or  ptgid == 0x44:
                result += 'REFERENCE '
                expression = expression[4:]
            else:
                break
        else:
            result += '??? '
            break
    if expression == '':
        return result
    else:
        return result + ' --- ' + repr(expression)

class cBIFF(cPluginParent):
    macroOnly = False
    name = 'BIFF plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []
        dOpcodes = {
            0x06: 'FORMULA : Cell Formula',
            0x0A: 'EOF : End of File',
            0x0C: 'CALCCOUNT : Iteration Count',
            0x0D: 'CALCMODE : Calculation Mode',
            0x0E: 'PRECISION : Precision',
            0x0F: 'REFMODE : Reference Mode',
            0x10: 'DELTA : Iteration Increment',
            0x11: 'ITERATION : Iteration Mode',
            0x12: 'PROTECT : Protection Flag',
            0x13: 'PASSWORD : Protection Password',
            0x14: 'HEADER : Print Header on Each Page',
            0x15: 'FOOTER : Print Footer on Each Page',
            0x16: 'EXTERNCOUNT : Number of External References',
            0x17: 'EXTERNSHEET : External Reference',
            0x18: 'LABEL : Cell Value, String Constant',
            0x19: 'WINDOWPROTECT : Windows Are Protected',
            0x1A: 'VERTICALPAGEBREAKS : Explicit Column Page Breaks',
            0x1B: 'HORIZONTALPAGEBREAKS : Explicit Row Page Breaks',
            0x1C: 'NOTE : Comment Associated with a Cell',
            0x1D: 'SELECTION : Current Selection',
            0x22: '1904 : 1904 Date System',
            0x26: 'LEFTMARGIN : Left Margin Measurement',
            0x27: 'RIGHTMARGIN : Right Margin Measurement',
            0x28: 'TOPMARGIN : Top Margin Measurement',
            0x29: 'BOTTOMMARGIN : Bottom Margin Measurement',
            0x2A: 'PRINTHEADERS : Print Row/Column Labels',
            0x2B: 'PRINTGRIDLINES : Print Gridlines Flag',
            0x2F: 'FILEPASS : File Is Password-Protected',
            0x3C: 'CONTINUE : Continues Long Records',
            0x3D: 'WINDOW1 : Window Information',
            0x40: 'BACKUP : Save Backup Version of the File',
            0x41: 'PANE : Number of Panes and Their Position',
            0x42: 'CODENAME : VBE Object Name',
            0x42: 'CODEPAGE : Default Code Page',
            0x4D: 'PLS : Environment-Specific Print Record',
            0x50: 'DCON : Data Consolidation Information',
            0x51: 'DCONREF : Data Consolidation References',
            0x52: 'DCONNAME : Data Consolidation Named References',
            0x55: 'DEFCOLWIDTH : Default Width for Columns',
            0x59: 'XCT : CRN Record Count',
            0x5A: 'CRN : Nonresident Operands',
            0x5B: 'FILESHARING : File-Sharing Information',
            0x5C: 'WRITEACCESS : Write Access User Name',
            0x5D: 'OBJ : Describes a Graphic Object',
            0x5E: 'UNCALCED : Recalculation Status',
            0x5F: 'SAVERECALC : Recalculate Before Save',
            0x60: 'TEMPLATE : Workbook Is a Template',
            0x63: 'OBJPROTECT : Objects Are Protected',
            0x7D: 'COLINFO : Column Formatting Information',
            0x7E: 'RK : Cell Value, RK Number',
            0x7F: 'IMDATA : Image Data',
            0x80: 'GUTS : Size of Row and Column Gutters',
            0x81: 'WSBOOL : Additional Workspace Information',
            0x82: 'GRIDSET : State Change of Gridlines Option',
            0x83: 'HCENTER : Center Between Horizontal Margins',
            0x84: 'VCENTER : Center Between Vertical Margins',
            0x85: 'BOUNDSHEET : Sheet Information',
            0x86: 'WRITEPROT : Workbook Is Write-Protected',
            0x87: 'ADDIN : Workbook Is an Add-in Macro',
            0x88: 'EDG : Edition Globals',
            0x89: 'PUB : Publisher',
            0x8C: 'COUNTRY : Default Country and WIN.INI Country',
            0x8D: 'HIDEOBJ : Object Display Options',
            0x90: 'SORT : Sorting Options',
            0x91: 'SUB : Subscriber',
            0x92: 'PALETTE : Color Palette Definition',
            0x94: 'LHRECORD : .WK? File Conversion Information',
            0x95: 'LHNGRAPH : Named Graph Information',
            0x96: 'SOUND : Sound Note',
            0x98: 'LPR : Sheet Was Printed Using LINE.PRINT(',
            0x99: 'STANDARDWIDTH : Standard Column Width',
            0x9A: 'FNGROUPNAME : Function Group Name',
            0x9B: 'FILTERMODE : Sheet Contains Filtered List',
            0x9C: 'FNGROUPCOUNT : Built-in Function Group Count',
            0x9D: 'AUTOFILTERINFO : Drop-Down Arrow Count',
            0x9E: 'AUTOFILTER : AutoFilter Data',
            0xA0: 'SCL : Window Zoom Magnification',
            0xA1: 'SETUP : Page Setup',
            0xA9: 'COORDLIST : Polygon Object Vertex Coordinates',
            0xAB: 'GCW : Global Column-Width Flags',
            0xAE: 'SCENMAN : Scenario Output Data',
            0xAF: 'SCENARIO : Scenario Data',
            0xB0: 'SXVIEW : View Definition',
            0xB1: 'SXVD : View Fields',
            0xB2: 'SXVI : View Item',
            0xB4: 'SXIVD : Row/Column Field IDs',
            0xB5: 'SXLI : Line Item Array',
            0xB6: 'SXPI : Page Item',
            0xB8: 'DOCROUTE : Routing Slip Information',
            0xB9: 'RECIPNAME : Recipient Name',
            0xBC: 'SHRFMLA : Shared Formula',
            0xBD: 'MULRK : Multiple  RK Cells',
            0xBE: 'MULBLANK : Multiple Blank Cells',
            0xC1: 'MMS :  ADDMENU / DELMENU Record Group Count',
            0xC2: 'ADDMENU : Menu Addition',
            0xC3: 'DELMENU : Menu Deletion',
            0xC5: 'SXDI : Data Item',
            0xC6: 'SXDB : PivotTable Cache Data',
            0xCD: 'SXSTRING : String',
            0xD0: 'SXTBL : Multiple Consolidation Source Info',
            0xD1: 'SXTBRGIITM : Page Item Name Count',
            0xD2: 'SXTBPG : Page Item Indexes',
            0xD3: 'OBPROJ : Visual Basic Project',
            0xD5: 'SXIDSTM : Stream ID',
            0xD6: 'RSTRING : Cell with Character Formatting',
            0xD7: 'DBCELL : Stream Offsets',
            0xDA: 'BOOKBOOL : Workbook Option Flag',
            0xDC: 'PARAMQRY : Query Parameters',
            0xDC: 'SXEXT : External Source Information',
            0xDD: 'SCENPROTECT : Scenario Protection',
            0xDE: 'OLESIZE : Size of OLE Object',
            0xDF: 'UDDESC : Description String for Chart Autoformat',
            0xE0: 'XF : Extended Format',
            0xE1: 'INTERFACEHDR : Beginning of User Interface Records',
            0xE2: 'INTERFACEEND : End of User Interface Records',
            0xE3: 'SXVS : View Source',
            0xE5: 'MERGECELLS : Merged Cells',
            0xEA: 'TABIDCONF : Sheet Tab ID of Conflict History',
            0xEB: 'MSODRAWINGGROUP : Microsoft Office Drawing Group',
            0xEC: 'MSODRAWING : Microsoft Office Drawing',
            0xED: 'MSODRAWINGSELECTION : Microsoft Office Drawing Selection',
            0xF0: 'SXRULE : PivotTable Rule Data',
            0xF1: 'SXEX : PivotTable View Extended Information',
            0xF2: 'SXFILT : PivotTable Rule Filter',
            0xF4: 'SXDXF : Pivot Table Formatting',
            0xF5: 'SXITM : Pivot Table Item Indexes',
            0xF6: 'SXNAME : PivotTable Name',
            0xF7: 'SXSELECT : PivotTable Selection Information',
            0xF8: 'SXPAIR : PivotTable Name Pair',
            0xF9: 'SXFMLA : Pivot Table Parsed Expression',
            0xFB: 'SXFORMAT : PivotTable Format Record',
            0xFC: 'SST : Shared String Table',
            0xFD: 'LABELSST : Cell Value, String Constant/ SST',
            0xFF: 'EXTSST : Extended Shared String Table',
            0x100: 'SXVDEX : Extended PivotTable View Fields',
            0x103: 'SXFORMULA : PivotTable Formula Record',
            0x122: 'SXDBEX : PivotTable Cache Data',
            0x13D: 'TABID : Sheet Tab Index Array',
            0x160: 'USESELFS : Natural Language Formulas Flag',
            0x161: 'DSF : Double Stream File',
            0x162: 'XL5MODIFY : Flag for  DSF',
            0x1A5: 'FILESHARING2 : File-Sharing Information for Shared Lists',
            0x1A9: 'USERBVIEW : Workbook Custom View Settings',
            0x1AA: 'USERSVIEWBEGIN : Custom View Settings',
            0x1AB: 'USERSVIEWEND : End of Custom View Records',
            0x1AD: 'QSI : External Data Range',
            0x1AE: 'SUPBOOK : Supporting Workbook',
            0x1AF: 'PROT4REV : Shared Workbook Protection Flag',
            0x1B0: 'CONDFMT : Conditional Formatting Range Information',
            0x1B1: 'CF : Conditional Formatting Conditions',
            0x1B2: 'DVAL : Data Validation Information',
            0x1B5: 'DCONBIN : Data Consolidation Information',
            0x1B6: 'TXO : Text Object',
            0x1B7: 'REFRESHALL : Refresh Flag',
            0x1B8: 'HLINK : Hyperlink',
            0x1BB: 'SXFDBTYPE : SQL Datatype Identifier',
            0x1BC: 'PROT4REVPASS : Shared Workbook Protection Password',
            0x1BE: 'DV : Data Validation Criteria',
            0x1C0: 'EXCEL9FILE : Excel 9 File',
            0x1C1: 'RECALCID : Recalc Information',
            0x200: 'DIMENSIONS : Cell Table Size',
            0x201: 'BLANK : Cell Value, Blank Cell',
            0x203: 'NUMBER : Cell Value, Floating-Point Number',
            0x204: 'LABEL : Cell Value, String Constant',
            0x205: 'BOOLERR : Cell Value, Boolean or Error',
            0x207: 'STRING : String Value of a Formula',
            0x208: 'ROW : Describes a Row',
            0x20B: 'INDEX : Index Record',
            0x218: 'NAME : Defined Name',
            0x221: 'ARRAY : Array-Entered Formula',
            0x223: 'EXTERNNAME : Externally Referenced Name',
            0x225: 'DEFAULTROWHEIGHT : Default Row Height',
            0x231: 'FONT : Font Description',
            0x236: 'TABLE : Data Table',
            0x23E: 'WINDOW2 : Sheet Window Information',
            0x293: 'STYLE : Style Information',
            0x406: 'FORMULA : Cell Formula',
            0x41E: 'FORMAT : Number Format',
            0x800: 'HLINKTOOLTIP : Hyperlink Tooltip',
            0x801: 'WEBPUB : Web Publish Item',
            0x802: 'QSISXTAG : PivotTable and Query Table Extensions',
            0x803: 'DBQUERYEXT : Database Query Extensions',
            0x804: 'EXTSTRING :  FRT String',
            0x805: 'TXTQUERY : Text Query Information',
            0x806: 'QSIR : Query Table Formatting',
            0x807: 'QSIF : Query Table Field Formatting',
            0x809: 'BOF : Beginning of File',
            0x80A: 'OLEDBCONN : OLE Database Connection',
            0x80B: 'WOPT : Web Options',
            0x80C: 'SXVIEWEX : Pivot Table OLAP Extensions',
            0x80D: 'SXTH : PivotTable OLAP Hierarchy',
            0x80E: 'SXPIEX : OLAP Page Item Extensions',
            0x80F: 'SXVDTEX : View Dimension OLAP Extensions',
            0x810: 'SXVIEWEX9 : Pivot Table Extensions',
            0x812: 'CONTINUEFRT : Continued  FRT',
            0x813: 'REALTIMEDATA : Real-Time Data (RTD)',
            0x862: 'SHEETEXT : Extra Sheet Info',
            0x863: 'BOOKEXT : Extra Book Info',
            0x864: 'SXADDL : Pivot Table Additional Info',
            0x865: 'CRASHRECERR : Crash Recovery Error',
            0x866: 'HFPicture : Header / Footer Picture',
            0x867: 'FEATHEADR : Shared Feature Header',
            0x868: 'FEAT : Shared Feature Record',
            0x86A: 'DATALABEXT : Chart Data Label Extension',
            0x86B: 'DATALABEXTCONTENTS : Chart Data Label Extension Contents',
            0x86C: 'CELLWATCH : Cell Watch',
            0x86d: 'FEATINFO : Shared Feature Info Record',
            0x871: 'FEATHEADR11 : Shared Feature Header 11',
            0x872: 'FEAT11 : Shared Feature 11 Record',
            0x873: 'FEATINFO11 : Shared Feature Info 11 Record',
            0x874: 'DROPDOWNOBJIDS : Drop Down Object',
            0x875: 'CONTINUEFRT11 : Continue  FRT 11',
            0x876: 'DCONN : Data Connection',
            0x877: 'LIST12 : Extra Table Data Introduced in Excel 2007',
            0x878: 'FEAT12 : Shared Feature 12 Record',
            0x879: 'CONDFMT12 : Conditional Formatting Range Information 12',
            0x87A: 'CF12 : Conditional Formatting Condition 12',
            0x87B: 'CFEX : Conditional Formatting Extension',
            0x87C: 'XFCRC : XF Extensions Checksum',
            0x87D: 'XFEXT : XF Extension',
            0x87E: 'EZFILTER12 : AutoFilter Data Introduced in Excel 2007',
            0x87F: 'CONTINUEFRT12 : Continue FRT 12',
            0x881: 'SXADDL12 : Additional Workbook Connections Information',
            0x884: 'MDTINFO : Information about a Metadata Type',
            0x885: 'MDXSTR : MDX Metadata String',
            0x886: 'MDXTUPLE : Tuple MDX Metadata',
            0x887: 'MDXSET : Set MDX Metadata',
            0x888: 'MDXPROP : Member Property MDX Metadata',
            0x889: 'MDXKPI : Key Performance Indicator MDX Metadata',
            0x88A: 'MDTB : Block of Metadata Records',
            0x88B: 'PLV : Page Layout View Settings in Excel 2007',
            0x88C: 'COMPAT12 : Compatibility Checker 12',
            0x88D: 'DXF : Differential XF',
            0x88E: 'TABLESTYLES : Table Styles',
            0x88F: 'TABLESTYLE : Table Style',
            0x890: 'TABLESTYLEELEMENT : Table Style Element',
            0x892: 'STYLEEXT : Named Cell Style Extension',
            0x893: 'NAMEPUBLISH : Publish To Excel Server Data for Name',
            0x894: 'NAMECMT : Name Comment',
            0x895: 'SORTDATA12 : Sort Data 12',
            0x896: 'THEME : Theme',
            0x897: 'GUIDTYPELIB : VB Project Typelib GUID',
            0x898: 'FNGRP12 : Function Group',
            0x899: 'NAMEFNGRP12 : Extra Function Group',
            0x89A: 'MTRSETTINGS : Multi-Threaded Calculation Settings',
            0x89B: 'COMPRESSPICTURES : Automatic Picture Compression Mode',
            0x89C: 'HEADERFOOTER : Header Footer',
            0x8A3: 'FORCEFULLCALCULATION : Force Full Calculation Settings',
            0x8c1: 'LISTOBJ : List Object',
            0x8c2: 'LISTFIELD : List Field',
            0x8c3: 'LISTDV : List Data Validation',
            0x8c4: 'LISTCONDFMT : List Conditional Formatting',
            0x8c5: 'LISTCF : List Cell Formatting',
            0x8c6: 'FMQRY : Filemaker queries',
            0x8c7: 'FMSQRY : File maker queries',
            0x8c8: 'PLV : Page Layout View in Mac Excel 11',
            0x8c9: 'LNEXT : Extension information for borders in Mac Office 11',
            0x8ca: 'MKREXT : Extension information for markers in Mac Office 11'
        }

        if self.streamname in [['Workbook'], ['Book']]:
            self.ran = True
            stream = self.stream

            oParser = optparse.OptionParser()
            oParser.add_option('-s', '--strings', action='store_true', default=False, help='Dump strings')
            oParser.add_option('-a', '--hexascii', action='store_true', default=False, help='Dump hex ascii')
            oParser.add_option('-o', '--opcode', type=str, default='', help='Opcode to filter for')
            oParser.add_option('-f', '--find', type=str, default='', help='Content to search for')
            (options, args) = oParser.parse_args(self.options.split(' '))

            if options.find.startswith('0x'):
                options.find = binascii.a2b_hex(options.find[2:])

            while stream != '':
                formatcodes = 'HH'
                formatsize = struct.calcsize(formatcodes)
                opcode, length = struct.unpack(formatcodes, stream[0:formatsize])
                stream = stream[formatsize:]
                data = stream[:length]
                stream = stream[length:]

                if opcode in dOpcodes:
                    opcodename = dOpcodes[opcode]
                else:
                    opcodename = ''
                line = '%04x %6d %s' % (opcode, length, opcodename)

                # FORMULA record
                if opcode == 0x06 and len(data) >= 21:
                    formatcodes = 'HH'
                    formatsize = struct.calcsize(formatcodes)
                    row, column = struct.unpack(formatcodes, data[0:formatsize])
                    formatcodes = 'H'
                    formatsize = struct.calcsize(formatcodes)
                    length = struct.unpack(formatcodes, data[20:20 + formatsize])[0]
                    expression = data[22:]
                    line += ' - R%dC%d %d %s' % (row + 1, column + 1, length, ParseExpression(expression))

                # FORMULA record #a# difference BIFF4 and BIFF5+
                if opcode == 0x18 and len(data) >= 16:
                    if ord(data[0]) & 0x20:
                        dBuildInNames = {1: 'Auto_Open', 2: 'Auto_Close'}
                        code = ord(data[14])
                        if code == 0: #a# hack with BIFF8 Unicode
                            code = ord(data[15])
                        line += ' - build-in-name %d %s' % (code, dBuildInNames.get(code, '?'))
                    else:
                        pass
                        line += ' - %s' % (data[14:14+ord(data[3])])

                # BOUNDSHEET record
                if opcode == 0x85 and len(data) >= 6:
                    dSheetType = {0: 'worksheet or dialog sheet', 1: 'Excel 4.0 macro sheet', 2: 'chart', 6: 'Visual Basic module'}
                    dSheetState = {0: 'visible', 1: 'hidden', 2: 'very hidden'}
                    line += ' - %s, %s' % (dSheetType.get(ord(data[5]), '%02x' % ord(data[5])), dSheetState.get(ord(data[4]), '%02x' % ord(data[4])))

                if options.find == '' and options.opcode == '' or options.opcode != '' and options.opcode.lower() in line.lower() or options.find != '' and options.find in data:
                    result.append(line)

                    if options.hexascii:
                        result.extend(' ' + foundstring for foundstring in HexASCII(data, 8))
                    elif options.strings:
                        dEncodings = {'s': 'ASCII', 'L': 'UNICODE'}
                        for encoding, strings in Strings(data).items():
                            if len(strings) > 0:
                                result.append(' ' + dEncodings[encoding] + ':')
                                result.extend('  ' + foundstring for foundstring in strings)

        return result

AddPlugin(cBIFF)
