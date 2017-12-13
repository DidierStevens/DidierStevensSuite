#!/usr/bin/env python

__description__ = 'BIFF plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2017/12/12'

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

        if self.streamname == ['Workbook']:
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
                line = '%04x %6d %s ' % (opcode, length, opcodename)

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
