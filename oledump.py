#!/usr/bin/env python

__description__ = 'Analyze OLE files (Compound Binary Files)'
__author__ = 'Didier Stevens'
__version__ = '0.0.79'
__date__ = '2025/03/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

# http://www.wordarticles.com/Articles/Formats/StreamCompression.php

History:
  2014/08/21: start
  2014/08/22: added ZIP support
  2014/08/23: added stdin support
  2014/08/25: added options extract and info
  2014/08/26: bugfix pipe
  2014/09/01: added * as selection option
  2014/09/15: exception handling for import OleFileIO_PL
  2014/11/12: added plugins
  2014/11/15: continued plugins
  2014/11/21: added pluginoptions
  2014/12/14: 0.0.3: Added YARA support; added decoders
  2014/12/19: 0.0.4: fixed bug when file was not OLE
  2014/12/24: 0.0.5: fixed storage bug and added MacrosContainsOnlyAttributes
  2014/12/25: 0.0.6: added support for ZIP containers with OLE files, like .docx
  2014/12/26: added printing of filename OLE files inside ZIP
  2014/12/31: suppressed printing of filename when selecting
  2015/02/09: 0.0.7: added handling of .docx, ... inside ZIP file; Added option yarastrings
  2015/02/10: 0.0.8: added YARACompile
  2015/02/19: 0.0.9: added option -q
  2015/02/23: 0.0.10: handle errors in compressed macros
  2015/02/24: continue
  2015/03/02: 0.0.11: added option -M
  2015/03/05: added support for .xml files
  2015/03/11: 0.0.12: added code pages identification
  2015/03/13: Fixed oElement.firstChild.nodeValue UnicodeEncodeError bug
  2015/03/19: 0.0.13: added option -c
  2015/03/24: added man page
  2015/03/25: added option --decompress
  2015/03/26: changed --raw option
  2015/04/10: 0.0.14: fixed bug SearchAndDecompressSub
  2015/05/08: 0.0.15: added direct support for ActiveMime files
  2015/05/13: 0.0.16: changed HeuristicDecompress with findall; renamed MacrosContainsOnlyAttributes to MacrosContainsOnlyAttributesOrOptions
  2015/06/08: 0.0.17: Fix HexAsciiDump
  2015/06/14: Added exit code
  2015/07/26: 0.0.18: Added option --vbadecompresscorrupt
  2015/09/12: added option --cut
  2015/09/13: changed exit code to 2 when macros detected
  2015/09/16: Rename old OleFileIO_PL to new olefile so that local copy of the module can be used
  2015/09/17: added help for pip install olefile
  2015/09/22: fixed os.path.isfile(filename) bug
  2015/10/30: 0.0.19 added option -E and environment variable OLEDUMP_EXTRA; added MD5 to option -i
  2015/11/08: 0.0.20 added man text for option -E; changed OptionsEnvironmentVariables so option takes precedence over environment variable
  2015/11/09: continued -E
  2015/11/12: 0.0.21 added dslsimulationdb
  2015/11/17: added support for :-number in --cut option
  2015/12/16: 0.0.22 some enhancements for --raw option
  2015/12/22: 0.0.23 updated cut syntax
  2016/06/08: 0.0.24 option -v works with option -E
  2016/08/01: 0.0.25 added Magic to info
  2016/10/16: decompressed.replace('\r\n', '\n'); added plugindir and decoderdir options by Remi Pointel
  2016/12/11: 0.0.26 added indicator O for OLE10Native
  2017/03/04: 0.0.27 added externals for YARA rules
  2017/07/20: 0.0.28 added # to option -y
  2017/10/14: 0.0.29 added options -t, -S; and \x00Attribut bugfix provided by Charles Smutz
  2017/11/01: 0.0.30 replaced hexdump and hexasciidump with cDump
  2017/11/04: added return codes -1 and 1
  2017/12/13: 0.0.31 corrected man
  2017/12/16: 0.0.32 added indexQuiet to cPlugin
  2018/02/18: 0.0.33 added option -j
  2018/05/06: 0.0.34 -s is more userfriendly
  2018/07/01: 0.0.35 rename option --json to --jsonoutput
  2018/07/01: fix for json output with OOXML files
  2018/07/07: 0.0.36: updated to version 2 of jsonoutput
  2018/08/04: 0.0.37 added option --vbadecompressskipattributes
  2018/08/13: 0.0.38 changed output processing of plugins like plugin_ppt: if a plugin returns a string, that string is dumped with option -q
  2018/11/25: 0.0.39 started VBA/dir parsing for modules, to display with option -i
  2018/11/26: continued VBA/dir parsing for modules; added c and s selection; added selection warning; added option -A and option -T; added yara #x#
  2018/11/30: added yara #r#; updated ParseCutTerm
  2018/12/18: 0.0.40 added option --password
  2019/02/16: 0.0.41 updated Cut
  2019/03/12: 0.0.42 added warning for ZIP container without ole file; fixed selectiong warning
  2019/07/21: 0.0.43 added option --storages, %CLSID%, stream UNICODE name
  2019/11/04: fixed plugin path when compiled with pyinstaller
  2019/11/05: Python 3 support
  2019/11/24: changed HeuristicDecompress; Python 3 fixes
  2019/12/18: 0.0.44 added option -f
  2020/01/06: 0.0.45 added verbose YARACompile
  2020/03/06: 0.0.46 added %CLSIDDESC% and Root Entry to --storages
  2020/03/08: 0.0.47 updated man
  2020/03/09: 0.0.48 Python 3 bug fix
  2020/03/28: 0.0.49 -s (selection) is no longer case sensitive with letter prefixes
  2020/05/21: 0.0.50 fixed typos man page
  2020/07/18: 0.0.51 small fix ASCII dump: 0x7F is not printable
  2020/07/25: 0.0.52 added support for pyzipper
  2020/08/??: 0.0.53 added ole plugin class
  2020/08/28: added support to select streams by name
  2020/08/30: fixed & updated raw VBA decompression
  2020/09/05: 0.0.54 added extra info parameter %MODULEINFO%
  2020/09/29: bugfix for Python 2 (mro)
  2020/11/08: 0.0.55 added support for -v with --jsonoutput; added ! indicator
  2020/12/04: 0.0.56 Python 3 Fixes
  2020/12/12: 0.0.57 refactoring Translate
  2021/01/09: 0.0.58 updated man
  2021/02/06: 0.0.59 small change to XML detection logic
  2021/02/23: 0.0.60 small change PIP message
  2021/06/20: 0.0.61 updated man
  2021/08/11: 0.0.62 fix return code bug for multiple OLE files inside OOXML container
  2022/02/21: 0.0.63 Python 3 fix
  2022/03/04: 0.0.64 added option -u
  2022/04/26: 0.0.65 added message for pyzipper
  2022/05/03: 0.0.66 small refactoring
  2022/05/11: 0.0.67 added PrintUserdefinedProperties
  2022/06/07: 0.0.68 added extra info parameters %CTIME% %MTIME% %CTIMEHEX% %MTIMEHEX%
  2022/07/22: 0.0.69 minor documentation change
  2022/09/04: 0.0.70 bumping version for update to plugin(s), no changes to oledump.py
  2022/11/09: 0.0.71 bumping version for update to plugin(s), no changes to oledump.py
  2023/02/25: 0.0.72 added cStruct
  2023/03/23: 0.0.73 updated cStruct
  2023/04/01: 0.0.74 added CalculateChosenHash
  2023/05/01: 0.0.75 bumping version for update to plugin(s), no changes to oledump.py
  2024/05/15: 0.0.76 added cMyJSONOutput
  2024/07/11: 0.0.77 bumping version for update to plugin(s), no changes to oledump.py
  2024/12/24: 0.0.78 Python 3.12 fix mattew124
  2025/03/04: 0.0.79 fixed URL in man page kristofbaute

Todo:

"""

import optparse
import sys
import math
import os
import binascii
import xml.dom.minidom
import zlib
import hashlib
import textwrap
import re
import string
import codecs
import json
import struct
import datetime
import collections
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO

try:
    import yara
except ImportError:
    pass

try:
    import olefile
except ImportError:
    print('This program requires module olefile.\nhttp://www.decalage.info/python/olefileio\n')
    print("You can use PIP to install olefile like this: pip install olefile\nWindows: pip is located in Python's Scripts folder.\n")
    exit(-1)

try:
    from oletools.common.clsid import KNOWN_CLSIDS
except ImportError:
    KNOWN_CLSIDS = {}

try:
    import pyzipper as zipfile
except ImportError:
    import zipfile

dumplinelength = 16
MALWARE_PASSWORD = 'infected'
OLEFILE_MAGIC = b'\xD0\xCF\x11\xE0'
ACTIVEMIME_MAGIC = b'ActiveMime'
REGEX_STANDARD = b'[\x09\x20-\x7E]'

def PrintManual():
    manual = r'''
Manual:

oledump is a tool to analyze OLE files (officially: Compound File Binary Format, CFBF). Many file formats are in fact OLE files, like Microsoft Office files, MSI files, ... Even the new Microsoft Office Open XML (OOXML) format uses OLE files for VBA macros.
oledump can analyze OLE files directly, or indirectly when they are contained in some file format (like .docm, .xml, ...).

A cheat sheet can be found here: https://www.sans.org/posters/oledump-py-quick-reference/

oledump uses 2 modules that are not part of Python 2: olefile (http://www.decalage.info/python/olefileio) and YARA.
You need to install the olefile module for this program to work.
The YARA module is not mandatory if you don't use YARA rules.

Running oledump with a spreadsheet (.xls binary format) lists al the streams found in the OLE file (an OLE file is a virtual filesystem with folders and files, known as streams), like this:

C:\Demo>oledump.py Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation'
  2:      4096 '\\x05SummaryInformation'
  3:      4096 'Workbook'

The first column is an index assigned to the stream by oledump. This index is used to select streams. The second column is the size of the stream (number of bytes inside the stream), and the last column is the name of the stream.

To select a stream for analysis, use option -s with the index (number of the stream, or a for all streams), like this:
C:\Demo>oledump.py -s 1 Book1.xls
00000000: FE FF 00 00 05 01 02 00  00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  01 00 00 00 02 D5 CD D5  .............i-i
00000020: 9C 2E 1B 10 93 97 08 00  2B 2C F9 AE 30 00 00 00  ........+,..0...
00000030: E4 00 00 00 09 00 00 00  01 00 00 00 50 00 00 00  ............P...
00000040: 0F 00 00 00 58 00 00 00  17 00 00 00 70 00 00 00  ....X.......p...
...

When selecting a stream, its content is shown as an ASCII dump (this can also be done with option -a).
Option -x produces a hexadecimal dump instead of an ASCII dump.

C:\Demo>oledump.py -s 1 -x Book1.xls
FE FF 00 00 05 01 02 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 00 00 00 02 D5 CD D5
9C 2E 1B 10 93 97 08 00 2B 2C F9 AE 30 00 00 00
E4 00 00 00 09 00 00 00 01 00 00 00 50 00 00 00
0F 00 00 00 58 00 00 00 17 00 00 00 70 00 00 00
...

Option -A does an ASCII dump (like option -a), but with duplicate lines removed.

Option -S dumps the strings.

Option -d produces a raw dump of the content of the stream. This content can be redirected to a file, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls > content.bin

or it can be piped into another command, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls | pdfid.py -f

If the raw dump needs to be processed by a string codec, like utf16, use option -t instead of -d and provide the codec:
C:\Demo>oledump.py -s 1 -t utf16 Book1.xls

Streams can also be selected by their full name (example: -s 'VBA/ThisWorkkbook').

Option -C (--cut) allows for the partial selection of a stream. Use this option to "cut out" part of the stream.
The --cut option takes an argument to specify which section of bytes to select from the stream. This argument is composed of 2 terms separated by a colon (:), like this:
termA:termB
termA and termB can be:
- nothing (an empty string)
- a positive decimal number; example: 10
- an hexadecimal number (to be preceded by 0x); example: 0x10
- a case sensitive ASCII string to search for (surrounded by square brackets and single quotes); example: ['MZ']
- a case sensitive UNICODE string to search for (surrounded by square brackets and single quotes prefixed with u); example: [u'User']
- an hexadecimal string to search for (surrounded by square brackets); example: [d0cf11e0]
If termA is nothing, then the cut section of bytes starts with the byte at position 0.
If termA is a number, then the cut section of bytes starts with the byte at the position given by the number (first byte has index 0).
If termA is a string to search for, then the cut section of bytes starts with the byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
If termB is nothing, then the cut section of bytes ends with the last byte.
If termB is a number, then the cut section of bytes ends with the byte at the position given by the number (first byte has index 0).
When termB is a number, it can have suffix letter l. This indicates that the number is a length (number of bytes), and not a position.
termB can also be a negative number (decimal or hexademical): in that case the position is counted from the end of the file. For example, :-5 selects the complete file except the last 5 bytes.
If termB is a string to search for, then the cut section of bytes ends with the last byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
No checks are made to assure that the position specified by termA is lower than the position specified by termB. This is left up to the user.
Search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an instance (a number equal to 1 or greater) to indicate which instance needs to be taken. For example, ['ABC']2 will search for the second instance of string 'ABC'. If this instance is not found, then nothing is selected.
Search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an offset (+ or - a number) to add (or substract) an offset to the found instance. This number can be a decimal or hexadecimal (prefix 0x) value. For example, ['ABC']+3 will search for the first instance of string 'ABC' and then select the bytes after ABC (+ 3).
Finally, search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an instance and an offset.
Examples:
This argument can be used to dump the first 256 bytes of a PE file located inside the stream: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the stream: [d0cf11e0]:
When this option is not used, the complete stream is selected.

When analyzing a Microsoft Office document with VBA macros, you will see output similar to this:

C:\Demo>oledump.py Book2-vba.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:      2484 'Workbook'
  5:       529 '_VBA_PROJECT_CUR/PROJECT'
  6:       104 '_VBA_PROJECT_CUR/PROJECTwm'
  7: M    1196 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: m     977 '_VBA_PROJECT_CUR/VBA/Sheet2'
  9: m     977 '_VBA_PROJECT_CUR/VBA/Sheet3'
 10: m     985 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
 11:      2651 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:       549 '_VBA_PROJECT_CUR/VBA/dir'

The letter M next to the index of some of the streams (streams 7, 8, 9 and 10) is a macro indicator.
If you select a macro stream, the ASCII dump will not help you much. This is because of compression. VBA macros are stored inside streams using a proprietary compression method. To decompress the VBA macros source code, you use option -v, like this:
C:\Demo>oledump.py -s 7 -v Book2-vba.xls
Attribute VB_Name = "Sheet1"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
Sub Workbook_Open()
    MsgBox "VBA macro"
End Sub

If the VBA macro code is only composed of Attribute or Option statements, and no other statements, then the indicator is a lower case letter m. Example:
C:\Demo>oledump.py -s 8 -v Book2-vba.xls
Attribute VB_Name = "Sheet2"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True

If the VBA code contains other statements than Attribute or Options statements, then the indicator is a upper case letter M.
This M/m indicator allows you to focus first on interesting VBA macros.
A ! indicator means that the stream is a VBA module, but that no VBA code was detected that starts with one or more attributes.

To decompress the macros and skip the initial attributes, use option --vbadecompressskipattributes.

When compressed VBA code is corrupted, the status indicatore will be E (error).
C:\Demo>oledump.py Book2-vba.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:      2484 'Workbook'
  5:       529 '_VBA_PROJECT_CUR/PROJECT'
  6:       104 '_VBA_PROJECT_CUR/PROJECTwm'
  7: E    1196 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: m     977 '_VBA_PROJECT_CUR/VBA/Sheet2'
  9: m     977 '_VBA_PROJECT_CUR/VBA/Sheet3'
 10: m     985 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
 11:      2651 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:       549 '_VBA_PROJECT_CUR/VBA/dir'

To view the VBA code up til the corruption, use option --vbadecompresscorrupt.
C:\Demo>oledump.py -s 7 --vbadecompresscorrupt Book2-vba.xls

Option -i (without option -s) displays extra information for modules:
C:\Demo>oledump.py -i Book2-vba.xls
  1:       107             '\\x01CompObj'
  2:       256             '\\x05DocumentSummaryInformation'
  3:       216             '\\x05SummaryInformation'
  4:     15615             'Workbook'
  5:       435             '_VBA_PROJECT_CUR/PROJECT'
  6:        62             '_VBA_PROJECT_CUR/PROJECTwm'
  7: m     985     813+172 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: M    1767    1545+222 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
  9:      2413             '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 10:      1253             '_VBA_PROJECT_CUR/VBA/__SRP_0'
 11:       106             '_VBA_PROJECT_CUR/VBA/__SRP_1'
 12:       504             '_VBA_PROJECT_CUR/VBA/__SRP_2'
 13:       103             '_VBA_PROJECT_CUR/VBA/__SRP_3'
 14:       524             '_VBA_PROJECT_CUR/VBA/dir'

Modules can contain compiled code and source code (usually, both). In this example, stream 7 and 8 have extra information: the size of the compiled code (left of the + sign) and the size of de source code (right of the + sign).
Stream 7 is a module with size 985, the first 813 bytes are the compiled code and the last 172 bytes are the source code.

When selecting the content of modules, the index can be suffixed with c to select only the bytes of the compiled code, or with s to select only the bytes of the source code:
C:\Demo>oledump.py -s 7s Book2-vba.xls
00000000: 01 A8 B0 00 41 74 74 72  69 62 75 74 00 65 20 56  ....Attribut.e V
00000010: 42 5F 4E 61 6D 00 65 20  3D 20 22 53 68 65 40 65  B_Nam.e = "She@e
00000020: 74 31 22 0D 0A 0A E8 42  04 61 73 02 74 30 7B 30  t1"....B.as.t0{0
00000030: 30 30 C0 32 30 38 32 30  2D 00 20 04 08 0E 43 00  00.20820-. ...C.
00000040: 14 02 1C 01 24 30 30 34  36 02 7D 0D 7C 47 6C 6F  ....$0046.}.|Glo
00000050: 62 61 6C 21 01 C4 53 70  61 63 01 92 46 61 08 6C  bal!..Spac..Fa.l
00000060: 73 65 0C 64 43 72 65 61  10 74 61 62 6C 15 1F 50  se.dCrea.tabl..P
00000070: 72 65 20 64 65 63 6C 61  00 06 49 64 11 00 AB 54  re decla..Id...T
00000080: 72 75 0D 42 45 78 70 08  6F 73 65 14 1C 54 65 6D  ru.BExp.ose..Tem
00000090: 70 00 6C 61 74 65 44 65  72 69 06 76 02 24 92 42  p.lateDeri.v.$.B
000000A0: 75 73 74 6F 6D 0C 69 7A  04 44 03 32              ustom.iz.D.2

Option -r can be used together with option -v to decompress a VBA macro stream that was extracted through some other mean than oledump. In such case, you provide the file that contains the compressed macro, instead of the OLE file.

ole files can contain streams that are not connected to the root entry. This can happen when a maldoc is cleaned by anti-virus. oledump will mark such streams as orphaned:
C:\Demo>oledump.py Book2-vba.xls
  1:       114 '\\x01CompObj'
  2:    107608 '\\x05DocumentSummaryInformation'
  3:     52900 '\\x05SummaryInformation'
  4:     11288 '1Table'
  5:    131068 'Data'
  6:      7726 'WordDocument'
  7:       567 Orphan: 'dir'
  8:      2282 Orphan: '__SRP_0'
  9:        84 Orphan: '__SRP_1'
 10:      3100 Orphan: '__SRP_2'
 11:       188 Orphan: '__SRP_3'
 12: M    9443 Orphan: 'NewMacros'
 13: m     940 Orphan: 'ThisDocument'
 14:      3835 Orphan: 'XVBA_PROJECT'
 15:       484 Orphan: 'PROJECT'
 16:        71 Orphan: 'PROJECTwm'

Microsoft Office files can contain embedded objects. They show up like this (notice stream 6 Ole10Native with indicator O):
C:\Demo>oledump.py Book1-insert-object-calc-rol3.exe.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:        80 'MBD0004D0D1/\\x01CompObj'
  5:        20 'MBD0004D0D1/\\x01Ole'
  6: O  114798 'MBD0004D0D1/\\x01Ole10Native'
  7:     11312 'Workbook'

To get more info about the embedded object, use option -i like this:
C:\Demo>oledump.py -s 6 -i Book1-insert-object-calc-rol3.exe.xls
String 1: calc-rol3.exe
String 2: C:\Demo\ole\CALC-R~1.EXE
String 3: C:\Demo\ole\CALC-R~1.EXE
Size embedded file: 114688
MD5 embedded file: bef425b95e45c54d649a19a7c55556a0
SHA256 embedded file: 211b63ae126411545f9177ec80114883d32f7e3c7ccf81ee4e5dd6ffe3a10e2d

To extract the embedded file, use option -e and redirect the output to a file like this:
C:\Demo>oledump.py -s 6 -e Book1-insert-object-calc-rol3.exe.xls > extracted.bin

Use option --storages to display storages (by default, oledump only lists streams). Indicator . is used for storages except for the Root Entry which has indicator R.

Option -f can be used to find embedded OLE files. This is useful, for example, in the following scenario:
AutoCAD drawing files (.dwg) can contain VBA macros. Although the .dwg file format is a proprietary format, VBA macros are stored as an embedded OLE file. The header of a DWG file contains a pointer to the embedded OLE file, but since an OLE file starts with a MAGIC sequence (D0CF11E0), you can just scan the input file for this sequence.
This can be done using option -f (--find). This option takes a value: letter l or a positive integer.
To have an overview of embedded OLE files, use option "-f l" (letter l) like this:

C:\Demo>oledump.py -f l Drawing1vba.dwg
Position of potential embedded OLE files:
 1 0x00008090

This will report the position of every (potential) embedded OLE file inside the input file. Here you can see that there is one file at position 0x8090.
You can then select this file and analyze it, using -f 1 (integer 1):

C:\Demo>oledump.py -f 1 Drawing1vba.dwg
  1:       374 'VBA_Project/PROJECT'
  2:        38 'VBA_Project/PROJECTwm'
  3: M    1255 'VBA_Project/VBA/ThisDrawing'
  4:      1896 'VBA_Project/VBA/_VBA_PROJECT'
  5:       315 'VBA_Project/VBA/dir'
  6:        16 'VBA_Project_Version'

And then you can use option -s to select streams and analyze them.

Analyzing the content of streams (and VBA macros) can be quite challenging. To help with the analysis, oledump provides support for plugins and YARA rules.

plugins are Python programs that take the stream content as input and try to analyze it. Plugins can analyze the raw stream content or the decompressed VBA macro source code. Plugins analyze all streams, you don't need to select a particular stream.
VBA macros code in malicious documents is often obfuscated, and hard to understand. plugin_http_heuristics is a plugin for VBA macros that tries to recover the URL used to download the trojan in a malicious Office document. This URL is often obfuscated, for example by using hexadecimal or base64 strings to represent the URL. plugin_http_heuristics tries several heuristics to recover a URL.
Example:
C:\Demo>oledump.py -p plugin_http_heuristics sample.xls
  1:       104 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       228 '\\x05SummaryInformation'
  4:      4372 'Workbook'
  5:       583 '_VBA_PROJECT_CUR/PROJECT'
  6:        83 '_VBA_PROJECT_CUR/PROJECTwm'
  7: m     976 '_VBA_PROJECT_CUR/VBA/????1'
               Plugin: HTTP Heuristics plugin
  8: m     976 '_VBA_PROJECT_CUR/VBA/????2'
               Plugin: HTTP Heuristics plugin
  9: m     976 '_VBA_PROJECT_CUR/VBA/????3'
               Plugin: HTTP Heuristics plugin
 10: M  261251 '_VBA_PROJECT_CUR/VBA/????????'
               Plugin: HTTP Heuristics plugin
                 http://???.???.???.??:8080/stat/lld.php
 11:      8775 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:      1398 '_VBA_PROJECT_CUR/VBA/__SRP_0'
 13:       212 '_VBA_PROJECT_CUR/VBA/__SRP_1'
 14:       456 '_VBA_PROJECT_CUR/VBA/__SRP_2'
 15:       385 '_VBA_PROJECT_CUR/VBA/__SRP_3'
 16:       550 '_VBA_PROJECT_CUR/VBA/dir'

Option -q (quiet) only displays output from the plugins, it suppresses output from oledump. This makes it easier to spot URLs:
C:\Demo>oledump.py -p plugin_http_heuristics -q sample.xls
http://???.???.???.??:8080/stat/lld.php

When specifying plugins, you do not need to give the full path nor the .py extension (it's allowed though). If you just give the filename without a path, oledump will search for the plugin in the current directory and in the directory where oledump.py is located. You can specify more than one plugin by separating their names with a comma (,), or by using a at-file. A at-file is a text file containing the names of the plugins (one per line). If plugins are located in a different directory, you could specify it with the --plugindir option. To indicate to oledump that a text file is a at-file, you prefix iw with @, like this:
oledump.py -p @all-plugins.txt sample.xls

Some plugins take options too. Use --pluginoptions to specify these options.

oledump can scan the content of the streams with YARA rules (the YARA Python module must be installed). You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files. Or you can provide the YARA rule with the option value (and adhoc rule) if it starts with # (literal), #s# (string), #x# (hexadecimal string), #r# (regex string), #q# (quote), #h# (hexadecimal) or #b# (base64). Example: -y "#rule demo {strings: $a=\"demo\" condition: $a}"
Using #s#demo will instruct oledump to generate a rule to search for string demo (rule string {strings: $a = "demo" ascii wide nocase condition: $a) and use that rule.
All streams are scanned with the provided YARA rules, you can not use option -s to select an individual stream.

Example:
C:\Demo>oledump.py -y contains_pe_file.yara Book1-insert-object-exe.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule: Contains_PE_File
  6:     19567 'Workbook'

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) inside Microsoft Office files. The rule triggered for stream 5, because it contains an EXE file embedded as OLE object.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
C:\Demo>oledump.py -y contains_pe_file.yara --yarastrings Book1-insert-object-exe.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule: Contains_PE_File
               000064 $a:
                4d5a
                'MZ'
  6:     19567 'Workbook'

YARA rule contains_pe_file detects PE files by finding string MZ followed by string PE at the correct offset (AddressOfNewExeHeader).
The rule looks like this:
rule Contains_PE_File
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a PE file inside a byte sequence"
        method = "Find string MZ followed by string PE at the correct offset (AddressOfNewExeHeader)"
    strings:
        $a = "MZ"
    condition:
        for any i in (1..#a): (uint32(@a[i] + uint32(@a[i] + 0x3C)) == 0x00004550)
}

Distributed together with oledump are the YARA rules maldoc.yara. These are YARA rules to detect shellcode, based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

Two external variables are declared for use in YARA rules: streamname contains the stream name, and VBA is True when the YARA engine is given VBA source code to scan.

When looking for traces of Windows executable code (PE files, shellcode, ...) with YARA rules, one must take into account the fact that the executable code might have been encoded (for example via XOR and a key) to evade detection.
To deal with this possibility, oledump supports decoders. A decoder is another type of plugin, that will bruteforce a type of encoding on each stream. For example, decoder_xor1 will encode each stream via XOR and a key of 1 byte. So effectively, 256 different encodings of the stream will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
C:\Demo>oledump.py -y contains_pe_file.yara -D decoder_xor1 Book1-insert-object-exe-xor14.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule (stream decoder: XOR 1 byte key 0x14): Contains_PE_File
  6:     19567 'Workbook'

The YARA rule triggers on stream 5. It contains a PE file encoded via XORing each byte with 0x14.

You can specify decoders in exactly the same way as plugins, for example specifying more than one decoder separated by a comma ,.
If decoders are located in a different directory, you could specify it with the --decoderdir option.
C:\Demo>oledump.py -y contains_pe_file.yara -D decoder_xor1,decoder_rol1,decoder_add1 Book1-insert-object-exe-xor14.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule (stream decoder: XOR 1 byte key 0x14): Contains_PE_File
  6:     19567 'Workbook'

Some decoders take options, to be provided with option --decoderoptions.

OLE files contain metadata. Use option -M to display it.

Example:
C:\Demo>oledump.py -M Book1.xls
Properties SummaryInformation:
 codepage: 1252 ANSI Latin 1; Western European (Windows)
 author: Didier Stevens
 last_saved_by: Didier Stevens
 create_time: 2014-08-21 09:16:10
 last_saved_time: 2014-08-21 10:26:40
 creating_application: Microsoft Excel
 security: 0
Properties DocumentSummaryInformation:
 codepage_doc: 1252 ANSI Latin 1; Western European (Windows)
 scale_crop: False
 company: Didier Stevens Labs
 links_dirty: False
 shared_doc: False
 hlinks_changed: False
 version: 730895

Option -c calculates extra data per stream. This data is displayed per stream. Only the MD5 hash of the content of the stream is calculated.
Example:
C:\Demo>oledump.py -c Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation' ff1773dce227027d410b09f8f3224a56
  2:      4096 '\\x05SummaryInformation' b46068f38a3294ca9163442cb8271028
  3:      4096 'Workbook' d6a5bebba74fb1adf84c4ee66b2bf8dd

If you need more data than the MD5 of each stream, use option -E (extra). This option takes a parameter describing the extra data that needs to be calculated and displayed for each stream. The following variables are defined:
  %INDEX%: the index of the stream
  %INDICATOR%: macro indicator
  %LENGTH%': the length of the stream
  %NAME%: the printable name of the stream
  %MD5%: calculates MD5 hash
  %SHA1%: calculates SHA1 hash
  %SHA256%: calculates SHA256 hash
  %ENTROPY%: calculates entropy
  %HEADHEX%: display first 20 bytes of the stream as hexadecimal
  %HEADASCII%: display first 20 bytes of the stream as ASCII
  %TAILHEX%: display last 20 bytes of the stream as hexadecimal
  %TAILASCII%: display last 20 bytes of the stream as ASCII
  %HISTOGRAM%: calculates a histogram
                 this is the prevalence of each byte value (0x00 through 0xFF)
                 at least 3 numbers are displayed separated by a comma:
                 number of values with a prevalence > 0
                 minimum values with a prevalence > 0
                 maximum values with a prevalence > 0
                 each value with a prevalence > 0
  %BYTESTATS%: calculates byte statistics
                 byte statistics are 5 numbers separated by a comma:
                 number of NULL bytes
                 number of control bytes
                 number of whitespace bytes
                 number of printable bytes
                 number of high bytes
  %CLSID%: storage/stream class ID
  %CLSIDDESC%: storage/stream class ID description
  %MODULEINFO%: for module streams: size of compiled code & size of compressed code; otherwise 'N/A' (you must use option -i)
  %CTIME%: creation time
  %MTIME%: modification time
  %CTIMEHEX%: creation time in hexadecimal
  %MTIMEHEX%: modification time in hexadecimal

The parameter for -E may contain other text than the variables, which will be printed. Escape characters \\n and \\t are supported.
Example displaying the MD5 and SHA256 hash per stream, separated by a space character:
C:\Demo>oledump.py -E "%MD5% %SHA256%" Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation' ff1773dce227027d410b09f8f3224a56 2817c0fbe2931a562be17ed163775ea5e0b12aac203a095f51ffdbd5b27e7737
  2:      4096 '\\x05SummaryInformation' b46068f38a3294ca9163442cb8271028 2c3009a215346ae5163d5776ead3102e49f6b5c4d29bd1201e9a32d3bfe52723
  3:      4096 'Workbook' d6a5bebba74fb1adf84c4ee66b2bf8dd 82157e87a4e70920bf8975625f636d84101bbe8f07a998bc571eb8fa32d3a498

If the extra parameter starts with !, then it replaces the complete output line (in stead of being appended to the output line).
Example:
C:\Demo>oledump.py -E "!%INDEX% %MD5%" Book1.xls
1 ff1773dce227027d410b09f8f3224a56
2 b46068f38a3294ca9163442cb8271028
3 d6a5bebba74fb1adf84c4ee66b2bf8dd

Option -v can be used together with option -c or -E to perform the calculations on the decompressed macro streams (m and M) in stead of the raw macro streams.

To include extra data with each use of oledump, define environment variable OLEDUMP_EXTRA with the parameter that should be passed to -E. When environment variable OLEDUMP_EXTRA is defined, option -E can be ommited. When option -E is used together with environment variable OLEDUMP_EXTRA, the parameter of option -E is used and the environment variable is ignored.

Sometimes during the analysis of an OLE file, you might come across compressed data inside the stream. For example, an indicator of ZLIB compressed DATA is byte 0x78.
Option --decompress instructs oledump to search for compressed data inside the selected stream, and then decompress it. If this fails, the original data is displayed.

Option -u can be used to include unused data found in the last sector of a stream, after the stream data.

oledump can handle several types of files. OLE files are supported, but also the new Office Open XML standard: these are XML files inside a ZIP container, but VBA macros are still stored as OLE files inside the ZIP file. In such case, the name of the OLE file inside the ZIP file will be displayed, and the indices will be prefixed by a letter (A for the first OLE file, B for the second OLE file, ...).
Example:
C:\Demo>oledump.py Book1.xlsm
A: xl/vbaProject.bin
 A1:       462 'PROJECT'
 A2:        86 'PROJECTwm'
 A3: M     974 'VBA/Module1'
 A4: m     977 'VBA/Sheet1'
 A5: m     985 'VBA/ThisWorkbook'
 A6:      2559 'VBA/_VBA_PROJECT'
 A7:      1111 'VBA/__SRP_0'
 A8:        74 'VBA/__SRP_1'
 A9:       136 'VBA/__SRP_2'
A10:       103 'VBA/__SRP_3'
A11:       566 'VBA/dir'

oledump can also handle XML files that contain OLE files stored as base64 inside XML files.

Finally, all of these file types may be stored inside a password protected ZIP file (password infected). Storing malicious files inside a password protected ZIP file is common practice amongst malware researchers. Not only does it prevent accidental infection, but it also prevents anti-virus programs from deleting the sample.
oledump supports the analysis of samples stored in password protected ZIP files (password infected). Do not store more than one sample inside a password protected ZIP file. Each sample should be in its own ZIP container.

oledump also supports input/output redirection. This way, oledump can be used in a pipe.
Say for example that the sample OLE file is GZIP compressed. oledump can not handle GZIP files directly, but you can decompress and cat it with zcat and then pipe it into oledump for analysis, like this:
zcat sample.gz | oledump.py

With option -T (--headtail), output can be truncated to the first 10 lines and last 10 lines of output.

With option -j, oledump will output the content of the ole file as a JSON object that can be piped into other tools that support this JSON format. When option -v is used together with option -j, the produced JSON object contains decompressed VBA code.

Overview of indicators:
 M: Macro (attributes and code)
 m: macro (attributes without code)
 E: Error (code that throws an error when decompressed)
 !: Unusual macro (code without attributes)
 O: object (embedded file)
 .: storage
 R: root entry

More info: https://blog.didierstevens.com/2020/11/15/oledump-indicators/

The return codes of oledump are:
 -1 when an error occured
 0 when the file is not an ole file (or does not contain an ole file)
 1 when an ole file without macros was analyzed
 2 when an ole file with macros was analyzed
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 String If Python 3
def C2SIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return ''.join([chr(x) for x in string])
        else:
            return string
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

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def P23Chr(value):
    if type(value) == int:
        return chr(value)
    else:
        return value

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
            return P23Ord(data)

def HexDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump(rle=rle)

def Translate(expression):
    return lambda x: x.decode(expression)

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + b'{%d,}'
    return re.findall(regex % 4, data)

def ExtractStringsUNICODE(data):
    regex = b'((' + REGEX_STANDARD + b'\x00){%d,})'
    return [foundunicodestring.replace(b'\x00', b'') for foundunicodestring, dummy in re.findall(regex % 4, data)]

def ExtractStrings(data):
    return ExtractStringsASCII(data) + ExtractStringsUNICODE(data)

def DumpFunctionStrings(data):
    return b''.join([extractedstring + b'\n' for extractedstring in ExtractStrings(data)])

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(C2BIP3(data))
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

def PrintableName(fname, orphan=0):
    if orphan == 1:
        return 'Orphan: ' + repr(fname)
    else:
        return repr('/'.join(fname))

def ParseTokenSequence(data):
    flags = P23Ord(data[0])
    data = data[1:]
    result = []
    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[0:2])
                data = data[2:]
            else:
                result.append(data[0])
                data = data[1:]
    return result, data

def OffsetBits(data):
    numberOfBits = int(math.ceil(math.log(len(data), 2)))
    if numberOfBits < 4:
        numberOfBits = 4
    elif numberOfBits > 12:
        numberOfBits = 12
    return numberOfBits

def Bin(number):
    result = bin(number)[2:]
    while len(result) < 16:
        result = '0' + result
    return result

def DecompressChunk(compressedChunk):
    if len(compressedChunk) < 2:
        return None, None
    header = P23Ord(compressedChunk[0]) + P23Ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data.decode(errors='ignore'), compressedChunk[size:]

    decompressedChunk = ''
    while len(data) != 0:
        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if type(token) == int:
                decompressedChunk += chr(token)
            elif len(token) == 1:
                decompressedChunk += token
            else:
                if decompressedChunk == '':
                    return None, None
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = P23Ord(token[0]) + P23Ord(token[1]) * 0x100
                offset = 1 + (copyToken >> (16 - numberOfOffsetBits))
                length = 3 + (((copyToken << numberOfOffsetBits) & 0xFFFF) >> numberOfOffsetBits)
                copy = decompressedChunk[-offset:]
                copy = copy[0:length]
                lengthCopy = len(copy)
                while length > lengthCopy: #a#
                    if length - lengthCopy >= lengthCopy:
                        copy += copy[0:lengthCopy]
                        length -= lengthCopy
                    else:
                        copy += copy[0:length - lengthCopy]
                        length -= length - lengthCopy
                decompressedChunk += copy
    return decompressedChunk, compressedChunk[size:]

def Decompress(compressedData, replace=True):
    if P23Ord(compressedData[0]) != 1:
        return (False, None)
    remainder = compressedData[1:]
    decompressed = ''
    while len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        if decompressedChunk == None:
            return (False, decompressed)
        decompressed += decompressedChunk
    if replace:
        return (True, decompressed.replace('\r\n', '\n'))
    else:
        return (True, decompressed)

def FindCompression(data):
    return data.find(b'\x00Attribut\x00e ')

def SearchAndDecompressSub(data):
    position = FindCompression(data)
    if position == -1:
        return (False, '')
    else:
        compressedData = data[position - 3:]
    return Decompress(compressedData)

def SkipAttributes(text):
    oAttribute = re.compile('^Attribute VB_.+? = [^\n]+\n')
    while True:
        oMatch = oAttribute.match(text)
        if oMatch == None:
            break
        text = text[len(oMatch.group()):]
    return text

def SearchAndDecompress(data, ifError='Error: unable to decompress\n', skipAttributes=False):
    result, decompress = SearchAndDecompressSub(data)
    if result or ifError == None:
        if skipAttributes:
            return SkipAttributes(decompress)
        else:
            return decompress
    else:
        return ifError

def ReadWORD(data):
    if len(data) < 2:
        return None, None
    return P23Ord(data[0]) + P23Ord(data[1]) *0x100, data[2:]

def ReadDWORD(data):
    if len(data) < 4:
        return None, None
    return P23Ord(data[0]) + P23Ord(data[1]) *0x100 + P23Ord(data[2]) *0x10000 + P23Ord(data[3]) *0x1000000, data[4:]

def ReadNullTerminatedString(data):
    position = data.find(b'\x00')
    if position == -1:
        return None, None
    return data[:position], data[position + 1:]

def ExtractOle10Native(data):
    size, data = ReadDWORD(data)
    if size == None:
        return []
    dummy, data = ReadWORD(data)
    if dummy == None:
        return []
    filename, data = ReadNullTerminatedString(data)
    if filename == None:
        return []
    pathname, data = ReadNullTerminatedString(data)
    if pathname == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    dummy, data = ReadDWORD(data)
    if dummy == None:
        return []
    temppathname, data = ReadNullTerminatedString(data)
    if temppathname == None:
        return []
    sizeEmbedded, data = ReadDWORD(data)
    if sizeEmbedded == None:
        return []
    if len(data) < sizeEmbedded:
        return []

    return [filename, pathname, temppathname, data[:sizeEmbedded]]

def Extract(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return result[3]

def GenerateMAGIC(data):
    return binascii.b2a_hex(data) + b' ' + b''.join([IFF(P23Ord(c) >= 32 and P23Ord(c) < 127, C2BIP3(P23Chr(c)), b'.') for c in data])

def Info(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return 'String 1: %s\nString 2: %s\nString 3: %s\nSize embedded file: %d\nMD5 embedded file: %s\nSHA256 embedded file: %s\nMAGIC:  %s\nHeader: %s\n' % (result[0], result[1], result[2], len(result[3]), hashlib.md5(result[3]).hexdigest(), hashlib.sha256(result[3]).hexdigest(), GenerateMAGIC(result[3][0:4]), GenerateMAGIC(result[3][0:16]))

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
    global pluginsOle

    try:
        test = cClass.__mro__[1] == cPluginParent
    except AttributeError:
        test = True
    if test:
        plugins.append(cClass)
    else:
        pluginsOle.append(cClass)

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cPluginParent():
    macroOnly = False
    indexQuiet = False

class cPluginParentOle(object):
    macroOnly = False
    indexQuiet = False

    def __init__(self, ole, data, options):
        self.ole = ole
        self.data = data
        self.options = options

    def PreProcess(self):
        pass

    def Process(self, name, stream):
        pass

    def PostProcess(self):
        pass

def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])

def LoadPlugins(plugins, plugindir, verbose):
    if plugins == '':
        return

    if plugindir == '':
        scriptPath = GetScriptPath()
    else:
        scriptPath = plugindir

    for plugin in sum(map(ProcessAt, plugins.split(',')), []):
        try:
            if not plugin.lower().endswith('.py'):
                plugin += '.py'
            if os.path.dirname(plugin) == '':
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec(open(plugin, 'r').read(), globals(), globals())
        except Exception as e:
            print('Error loading plugin: %s' % plugin)
            if verbose:
                raise e

def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)

class cDecoderParent():
    pass

def LoadDecoders(decoders, decoderdir, verbose):
    if decoders == '':
        return

    if decoderdir == '':
        scriptPath = GetScriptPath()
    else:
        scriptPath = decoderdir

    for decoder in sum(map(ProcessAt, decoders.split(',')), []):
        try:
            if not decoder.lower().endswith('.py'):
                decoder += '.py'
            if os.path.dirname(decoder) == '':
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, 'r').read(), globals(), globals())
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

def MacrosContainsOnlyAttributesOrOptions(stream):
    lines = SearchAndDecompress(stream).split('\n')
    for line in [line.strip() for line in lines]:
        if line != '' and not line.startswith('Attribute ') and not line == 'Option Explicit':
            return False
    return True

#https://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx
dCodepages = {
    37: 'IBM EBCDIC US-Canada',
    437: 'OEM United States',
    500: 'IBM EBCDIC International',
    708: 'Arabic (ASMO 708)',
    709: 'Arabic (ASMO-449+, BCON V4)',
    710: 'Arabic - Transparent Arabic',
    720: 'Arabic (Transparent ASMO); Arabic (DOS)',
    737: 'OEM Greek (formerly 437G); Greek (DOS)',
    775: 'OEM Baltic; Baltic (DOS)',
    850: 'OEM Multilingual Latin 1; Western European (DOS)',
    852: 'OEM Latin 2; Central European (DOS)',
    855: 'OEM Cyrillic (primarily Russian)',
    857: 'OEM Turkish; Turkish (DOS)',
    858: 'OEM Multilingual Latin 1 + Euro symbol',
    860: 'OEM Portuguese; Portuguese (DOS)',
    861: 'OEM Icelandic; Icelandic (DOS)',
    862: 'OEM Hebrew; Hebrew (DOS)',
    863: 'OEM French Canadian; French Canadian (DOS)',
    864: 'OEM Arabic; Arabic (864)',
    865: 'OEM Nordic; Nordic (DOS)',
    866: 'OEM Russian; Cyrillic (DOS)',
    869: 'OEM Modern Greek; Greek, Modern (DOS)',
    870: 'IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2',
    874: 'ANSI/OEM Thai (ISO 8859-11); Thai (Windows)',
    875: 'IBM EBCDIC Greek Modern',
    932: 'ANSI/OEM Japanese; Japanese (Shift-JIS)',
    936: 'ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)',
    949: 'ANSI/OEM Korean (Unified Hangul Code)',
    950: 'ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)',
    1026: 'IBM EBCDIC Turkish (Latin 5)',
    1047: 'IBM EBCDIC Latin 1/Open System',
    1140: 'IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro)',
    1141: 'IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro)',
    1142: 'IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro)',
    1143: 'IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro)',
    1144: 'IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro)',
    1145: 'IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro)',
    1146: 'IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro)',
    1147: 'IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro)',
    1148: 'IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro)',
    1149: 'IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro)',
    1200: 'Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications',
    1201: 'Unicode UTF-16, big endian byte order; available only to managed applications',
    1250: 'ANSI Central European; Central European (Windows)',
    1251: 'ANSI Cyrillic; Cyrillic (Windows)',
    1252: 'ANSI Latin 1; Western European (Windows)',
    1253: 'ANSI Greek; Greek (Windows)',
    1254: 'ANSI Turkish; Turkish (Windows)',
    1255: 'ANSI Hebrew; Hebrew (Windows)',
    1256: 'ANSI Arabic; Arabic (Windows)',
    1257: 'ANSI Baltic; Baltic (Windows)',
    1258: 'ANSI/OEM Vietnamese; Vietnamese (Windows)',
    1361: 'Korean (Johab)',
    10000: 'MAC Roman; Western European (Mac)',
    10001: 'Japanese (Mac)',
    10002: 'MAC Traditional Chinese (Big5); Chinese Traditional (Mac)',
    10003: 'Korean (Mac)',
    10004: 'Arabic (Mac)',
    10005: 'Hebrew (Mac)',
    10006: 'Greek (Mac)',
    10007: 'Cyrillic (Mac)',
    10008: 'MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)',
    10010: 'Romanian (Mac)',
    10017: 'Ukrainian (Mac)',
    10021: 'Thai (Mac)',
    10029: 'MAC Latin 2; Central European (Mac)',
    10079: 'Icelandic (Mac)',
    10081: 'Turkish (Mac)',
    10082: 'Croatian (Mac)',
    12000: 'Unicode UTF-32, little endian byte order; available only to managed applications',
    12001: 'Unicode UTF-32, big endian byte order; available only to managed applications',
    20000: 'CNS Taiwan; Chinese Traditional (CNS)',
    20001: 'TCA Taiwan',
    20002: 'Eten Taiwan; Chinese Traditional (Eten)',
    20003: 'IBM5550 Taiwan',
    20004: 'TeleText Taiwan',
    20005: 'Wang Taiwan',
    20105: 'IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5)',
    20106: 'IA5 German (7-bit)',
    20107: 'IA5 Swedish (7-bit)',
    20108: 'IA5 Norwegian (7-bit)',
    20127: 'US-ASCII (7-bit)',
    20261: 'T.61',
    20269: 'ISO 6937 Non-Spacing Accent',
    20273: 'IBM EBCDIC Germany',
    20277: 'IBM EBCDIC Denmark-Norway',
    20278: 'IBM EBCDIC Finland-Sweden',
    20280: 'IBM EBCDIC Italy',
    20284: 'IBM EBCDIC Latin America-Spain',
    20285: 'IBM EBCDIC United Kingdom',
    20290: 'IBM EBCDIC Japanese Katakana Extended',
    20297: 'IBM EBCDIC France',
    20420: 'IBM EBCDIC Arabic',
    20423: 'IBM EBCDIC Greek',
    20424: 'IBM EBCDIC Hebrew',
    20833: 'IBM EBCDIC Korean Extended',
    20838: 'IBM EBCDIC Thai',
    20866: 'Russian (KOI8-R); Cyrillic (KOI8-R)',
    20871: 'IBM EBCDIC Icelandic',
    20880: 'IBM EBCDIC Cyrillic Russian',
    20905: 'IBM EBCDIC Turkish',
    20924: 'IBM EBCDIC Latin 1/Open System (1047 + Euro symbol)',
    20932: 'Japanese (JIS 0208-1990 and 0212-1990)',
    20936: 'Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)',
    20949: 'Korean Wansung',
    21025: 'IBM EBCDIC Cyrillic Serbian-Bulgarian',
    21027: '(deprecated)',
    21866: 'Ukrainian (KOI8-U); Cyrillic (KOI8-U)',
    28591: 'ISO 8859-1 Latin 1; Western European (ISO)',
    28592: 'ISO 8859-2 Central European; Central European (ISO)',
    28593: 'ISO 8859-3 Latin 3',
    28594: 'ISO 8859-4 Baltic',
    28595: 'ISO 8859-5 Cyrillic',
    28596: 'ISO 8859-6 Arabic',
    28597: 'ISO 8859-7 Greek',
    28598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Visual)',
    28599: 'ISO 8859-9 Turkish',
    28603: 'ISO 8859-13 Estonian',
    28605: 'ISO 8859-15 Latin 9',
    29001: 'Europa 3',
    38598: 'ISO 8859-8 Hebrew; Hebrew (ISO-Logical)',
    50220: 'ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS)',
    50221: 'ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana)',
    50222: 'ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI)',
    50225: 'ISO 2022 Korean',
    50227: 'ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)',
    50229: 'ISO 2022 Traditional Chinese',
    50930: 'EBCDIC Japanese (Katakana) Extended',
    50931: 'EBCDIC US-Canada and Japanese',
    50933: 'EBCDIC Korean Extended and Korean',
    50935: 'EBCDIC Simplified Chinese Extended and Simplified Chinese',
    50936: 'EBCDIC Simplified Chinese',
    50937: 'EBCDIC US-Canada and Traditional Chinese',
    50939: 'EBCDIC Japanese (Latin) Extended and Japanese',
    51932: 'EUC Japanese',
    51936: 'EUC Simplified Chinese; Chinese Simplified (EUC)',
    51949: 'EUC Korean',
    51950: 'EUC Traditional Chinese',
    52936: 'HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)',
    54936: 'Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)',
    57002: 'ISCII Devanagari',
    57003: 'ISCII Bengali',
    57004: 'ISCII Tamil',
    57005: 'ISCII Telugu',
    57006: 'ISCII Assamese',
    57007: 'ISCII Oriya',
    57008: 'ISCII Kannada',
    57009: 'ISCII Malayalam',
    57010: 'ISCII Gujarati',
    57011: 'ISCII Punjabi',
    65000: 'Unicode (UTF-7)',
    65001: 'Unicode (UTF-8)'
}

def LookupCodepage(codepage):
    if codepage in dCodepages:
        return dCodepages[codepage]
    else:
        return ''

def MyRepr(stringArg):
    stringRepr = repr(stringArg)
    if "'" + stringArg + "'" != stringRepr:
        return stringRepr
    else:
        return stringArg

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def UnpackSub(self, format):
        if format.endswith('z'):
            format = format[:-1]
            sz = True
        else:
            sz = False
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if sz:
            result = result + (self.GetString0(), )
        return result

    def Unpack(self, format):
        result = self.UnpackSub(format)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def UnpackNamedtuple(self, format, typename, field_names):
        namedTuple = collections.namedtuple(typename, field_names)
        result = self.UnpackSub(format)
        return namedTuple(*result)

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        if len(result) < length:
            raise Exception('Not enough data')
        self.data = self.data[length:]
        return result

    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)

    def GetString0(self):
        position = self.data.find(b'\x00')
        if position == -1:
            raise Exception('Missing NUL byte')
        result = self.data[:position]
        self.data = self.data[position + 1:]
        return result

def HeuristicZlibDecompress(data):
    for position in FindAll(data, b'\x78'):
        try:
            return zlib.decompress(data[position:])
        except:
            pass
    return data

def HeuristicDecompress(data):
    status, decompresseddata = Decompress(data, False)
    if status:
        return C2BIP3(decompresseddata)
    else:
        return HeuristicZlibDecompress(data)

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

def Replace(string, dReplacements):
    if string in dReplacements:
        return dReplacements[string]
    else:
        return string

def ParseInteger(argument):
    sign = 1
    if argument.startswith('+'):
        argument = argument[1:]
    elif argument.startswith('-'):
        argument = argument[1:]
        sign = -1
    if argument.startswith('0x'):
        return sign * int(argument[2:], 16)
    else:
        return sign * int(argument)

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
        oMatch = re.match(r'\[([0-9a-f]+)\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?', argument, re.I)
    else:
        value = int(oMatch.group(1))
        if argument.startswith('-'):
            value = -value
        return CUTTERM_POSITION, value, argument[len(oMatch.group(0)):]
    if oMatch == None:
        oMatch = re.match(r"\[u?\'(.+?)\'\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception('Uneven length hexadecimal string')
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        if argument.startswith("[u'"):
            # convert ascii to unicode 16 byte sequence
            searchtext = oMatch.group(1).decode('unicode_escape').encode('utf16')[2:]
        else:
            searchtext = oMatch.group(1)
        return CUTTERM_FIND, (searchtext, int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

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

def Find(data, value, nth, startposition=-1):
    position = startposition
    while nth > 0:
        position = data.find(value, position + 1)
        if position == -1:
            return -1
        nth -= 1
    return position

def CutData(stream, cutArgument):
    if cutArgument == '':
        return [stream, None, None]

    typeLeft, valueLeft, typeRight, valueRight = ParseCutArgument(cutArgument)

    if typeLeft == None:
        return [stream, None, None]

    if typeLeft == CUTTERM_NOTHING:
        positionBegin = 0
    elif typeLeft == CUTTERM_POSITION:
        positionBegin = valueLeft
    elif typeLeft == CUTTERM_FIND:
        positionBegin = Find(stream, valueLeft[0], valueLeft[1])
        if positionBegin == -1:
            return ['', None, None]
        positionBegin += valueLeft[2]
    else:
        raise Exception('Unknown value typeLeft')

    if typeRight == CUTTERM_NOTHING:
        positionEnd = len(stream)
    elif typeRight == CUTTERM_POSITION and valueRight < 0:
        positionEnd = len(stream) + valueRight
    elif typeRight == CUTTERM_POSITION:
        positionEnd = valueRight + 1
    elif typeRight == CUTTERM_LENGTH:
        positionEnd = positionBegin + valueRight
    elif typeRight == CUTTERM_FIND:
        positionEnd = Find(stream, valueRight[0], valueRight[1], positionBegin)
        if positionEnd == -1:
            return ['', None, None]
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception('Unknown value typeRight')

    return [stream[positionBegin:positionEnd], positionBegin, positionEnd]

def RemoveLeadingEmptyLines(data):
    if data[0] == '':
        return RemoveLeadingEmptyLines(data[1:])
    else:
        return data

def RemoveTrailingEmptyLines(data):
    if data[-1] == '':
        return RemoveTrailingEmptyLines(data[:-1])
    else:
        return data

def HeadTail(data, apply):
    count = 10
    if apply:
        lines = RemoveTrailingEmptyLines(RemoveLeadingEmptyLines(data.split('\n')))
        if len(lines) <= count * 2:
            return data
        else:
            return '\n'.join(lines[0:count] + ['...'] + lines[-count:])
    else:
        return data

def ExtraInfoMD5(data):
    return hashlib.md5(data).hexdigest()

def ExtraInfoSHA1(data):
    return hashlib.sha1(data).hexdigest()

def ExtraInfoSHA256(data):
    return hashlib.sha256(data).hexdigest()

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    for iter in range(1, 0x21):
        if chr(iter) in string.whitespace:
            countWhitespaceBytes += dPrevalence[iter]
        else:
            countControlBytes += dPrevalence[iter]
    countControlBytes += dPrevalence[0x7F]
    countPrintableBytes = 0
    for iter in range(0x21, 0x7F):
        countPrintableBytes += dPrevalence[iter]
    countHighBytes = 0
    for iter in range(0x80, 0x100):
        countHighBytes += dPrevalence[iter]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
    return sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def ExtraInfoENTROPY(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%f' % entropy

def ExtraInfoHEADHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[:16]).decode()

def ExtraInfoHEADASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[:16]])

def ExtraInfoTAILHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[-16:]).decode()

def ExtraInfoTAILASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(b) >= 32 and P23Ord(b) < 127, P23Chr(b), '.') for b in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    result = []
    count = 0
    minimum = None
    maximum = None
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            result.append('0x%02x:%d' % (iter, dPrevalence[iter]))
            count += 1
            if minimum == None:
                minimum = iter
            else:
                minimum = min(minimum, iter)
            if maximum == None:
                maximum = iter
            else:
                maximum = max(maximum, iter)
    result.insert(0, '%d' % count)
    result.insert(1, IFF(minimum == None, '', '0x%02x' % minimum))
    result.insert(2, IFF(maximum == None, '', '0x%02x' % maximum))
    return ','.join(result)

def ExtraInfoBYTESTATS(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def FormatFiletime(filetime):
    if filetime == 0:
        return '0'

    FILETIME19700101 = 116444736000000000
    oDatetime = datetime.datetime.fromtimestamp((filetime - FILETIME19700101) / 10000000, datetime.timezone.utc)
    return oDatetime.isoformat()

def GenerateExtraInfo(extra, index, indicator, moduleinfo, name, entry_metadata, stream):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
        prefix = ''
    else:
        prefix = ' '
#    if indicator == ' ':
#        indicator = ''
    moduleinfo = moduleinfo.strip()
    if moduleinfo == '':
        moduleinfo = 'N/A'
    if KNOWN_CLSIDS == {}:
        clsidDesc = '<oletools missing>'
    else:
        clsidDesc = KNOWN_CLSIDS.get(entry_metadata[0].upper(), '')
    dExtras = {'%INDEX%': lambda x: index,
               '%INDICATOR%': lambda x: indicator,
               '%LENGTH%': lambda x: '%d' % len(stream),
               '%NAME%': lambda x: name,
               '%MD5%': ExtraInfoMD5,
               '%SHA1%': ExtraInfoSHA1,
               '%SHA256%': ExtraInfoSHA256,
               '%ENTROPY%': ExtraInfoENTROPY,
               '%HEADHEX%': ExtraInfoHEADHEX,
               '%HEADASCII%': ExtraInfoHEADASCII,
               '%TAILHEX%': ExtraInfoTAILHEX,
               '%TAILASCII%': ExtraInfoTAILASCII,
               '%HISTOGRAM%': ExtraInfoHISTOGRAM,
               '%BYTESTATS%': ExtraInfoBYTESTATS,
               '%CLSID%': lambda x: entry_metadata[0],
               '%CLSIDDESC%': lambda x: clsidDesc,
               '%MODULEINFO%': lambda x: moduleinfo,
               '%CTIME%': lambda x: FormatFiletime(entry_metadata[1]),
               '%MTIME%': lambda x: FormatFiletime(entry_metadata[2]),
               '%CTIMEHEX%': lambda x: '%016x' % entry_metadata[1],
               '%MTIMEHEX%': lambda x: '%016x' % entry_metadata[2],
              }
    for variable in dExtras:
        if variable in extra:
            extra = extra.replace(variable, dExtras[variable](stream))
    return prefix + extra.replace(r'\t', '\t').replace(r'\n', '\n')

def OLE10HeaderPresent(data):
    length = len(data)
    if length < 6:
        return False
    size, data = ReadDWORD(data)
    if size == None:
        return False
    if size + 4 != length:
        return False
    version, data = ReadWORD(data)
    return version ==2

def GetUnusedData(ole, fname):
    sid = ole._find(fname)
    entry = ole.direntries[sid]
    if entry.size < ole.minisectorcutoff:
        increase = ole.minisectorsize
    else:
        increase = ole.sectorsize
    currentsize = entry.size
    lendata = currentsize
    while True:
        currentsize += increase
        data = ole._open(entry.isectStart, currentsize).read()
        if len(data) == lendata:
            return data[entry.size:]
        else:
            lendata = len(data)

def OLEGetStreams(ole, storages, unuseddata):
    olestreams = []
    if storages:
        olestreams.append([0, [ole.root.name], ole.root.entry_type, [ole.root.clsid, ole.root.createTime, ole.root.modifyTime], '', 0])
    for fname in ole.listdir(storages=storages):
        unusedData = b''
        if ole.get_type(fname) == 1:
            data = b''
        else:
            data = ole.openstream(fname).read()
            if unuseddata:
                unusedData = GetUnusedData(ole, fname)
        direntry = ole.direntries[ole._find(fname)]
        olestreams.append([0, fname, ole.get_type(fname), [ole.getclsid(fname), direntry.createTime, direntry.modifyTime], data + unusedData, len(unusedData)])
    for sid in range(len(ole.direntries)):
        entry = ole.direntries[sid]
        if entry is None:
            entry = ole._load_direntry(sid)
            if entry.entry_type == 2:
                olestreams.append([1, entry.name, entry.entry_type, ['', 0, 0], ole._open(entry.isectStart, entry.size).read(), 0])
    return olestreams

def SelectPart(stream, part, moduleinfodata):
    if part == '':
        return stream
    if not part in ['c', 's']:
        return ''
    if moduleinfodata == None:
        return ''
    if part == 'c':
        return stream[:moduleinfodata[6]]
    else:
        return stream[moduleinfodata[6]:]

def ParseVBADIR(ole):
    vbadirinfo = []
    for fname in ole.listdir():
        if len(fname) >= 2 and fname[-2] == 'VBA' and fname[-1] == 'dir':
            vbadirinfo = [fname]
            status, vbadirdata = Decompress(ole.openstream(fname).read(), False)
            if status:
                for position in FindAll(vbadirdata, '\x0F\x00\x02\x00\x00\x00'):
                    result = struct.unpack('<HIHHIHH', C2BIP3(vbadirdata[position:][0:18]))
                    if result[3] == 0x13 and result[4] == 0x02 and result[6] == 0x19:
                        vbadirinfo.append(result[2])
                        moduledata = vbadirdata[position + 16:]
                        moduleinfo = {}
                        while len(moduledata) > 2 and moduledata[0:2] == '\x19\x00':
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            moduledata = moduledata[6:]
                            namerecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x47:
                                break
                            moduledata = moduledata[6:]
                            nameunicoderecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x1A:
                                break
                            moduledata = moduledata[6:]
                            streamnamerecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x32:
                                break
                            moduledata = moduledata[6:]
                            streamnameunicoderecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x1C:
                                break
                            moduledata = moduledata[6:]
                            docstringrecordrecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HI', C2BIP3(moduledata[0:6]))
                            if result[0] != 0x48:
                                break
                            moduledata = moduledata[6:]
                            docstringunicoderecordrecord = moduledata[0:result[1]]
                            moduledata = moduledata[result[1]:]
                            result = struct.unpack('<HII', C2BIP3(moduledata[0:10]))
                            if result[0] != 0x31 or result[1] != 0x04:
                                break
                            moduledata = moduledata[10:]
                            moduleoffset = result[2]
                            moduledata = moduledata[10 + 8 + 6:]
                            if moduledata[0:2] != '\x2B\x00':
                                moduledata = moduledata[6:]
                            if moduledata[0:2] != '\x2B\x00':
                                moduledata = moduledata[6:]
                            moduledata = moduledata[2 + 4:]
                            moduleinfo[streamnameunicoderecord] = [namerecord, nameunicoderecord, streamnamerecord, streamnameunicoderecord, docstringrecordrecord, docstringunicoderecordrecord, moduleoffset]
                        if moduleinfo != {}:
                            vbadirinfo.append(moduleinfo)
    return vbadirinfo

def PrintUserdefinedProperties(ole, streamname):
    if not 'get_userdefined_properties' in dir(ole):
        return
    userdefinedproperties = ole.get_userdefined_properties(streamname)
    if len(userdefinedproperties) > 0:
        print('User defined properties:')
        for userdefinedproperty in userdefinedproperties:
            print(' %s: %s' % (userdefinedproperty['property_name'], userdefinedproperty['value']))

class cMyJSONOutput():

    def __init__(self):
        self.items = []
        self.counter = 1

    def AddIdItem(self, id, name, data):
        self.items.append({'id': id, 'name': name, 'content': binascii.b2a_base64(data).strip(b'\n').decode()})

    def AddItem(self, name, data):
        self.AddIdItem(self.counter, name, data)
        self.counter += 1

    def GetJSON(self):
        return json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': self.items})

def OLESub(ole, data, prefix, rules, options):
    global plugins
    global pluginsOle
    global decoders

    returnCode = 1
    selectionCounter = 0

    if options.metadata:
        metadata = ole.get_metadata()
        print('Properties SummaryInformation:')
        for attribute in metadata.SUMMARY_ATTRIBS:
            value = getattr(metadata, attribute)
            if value != None:
                if attribute == 'codepage':
                    print(' %s: %s %s' % (attribute, value, LookupCodepage(value)))
                else:
                    print(' %s: %s' % (attribute, value))
        PrintUserdefinedProperties(ole, ['\x05SummaryInformation'])

        print('Properties DocumentSummaryInformation:')
        for attribute in metadata.DOCSUM_ATTRIBS:
            value = getattr(metadata, attribute)
            if value != None:
                if attribute == 'codepage_doc':
                    print(' %s: %s %s' % (attribute, value, LookupCodepage(value)))
                else:
                    print(' %s: %s' % (attribute, value))
        PrintUserdefinedProperties(ole, ['\x05DocumentSummaryInformation'])

        return (returnCode, 0)

    if options.jsonoutput:
        oMyJSONOutput = cMyJSONOutput()
        if options.vbadecompress:
            counter = 1
            for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
                vbacode = SearchAndDecompress(stream, '')
                if vbacode != '':
                    oMyJSONOutput.AddIdItem(counter, PrintableName(fname), vbacode.encode())
                counter += 1
        else:
            for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
                oMyJSONOutput.AddItem(PrintableName(fname), stream)
        print(oMyJSONOutput.GetJSON())
        return (returnCode, 0)

    vbadirinfo = ParseVBADIR(ole)
    if len(vbadirinfo) == 3:
        dModuleinfo = vbadirinfo[2]
    else:
        dModuleinfo = {}

    if options.select == '':
        counter = 1
        vbaConcatenate = ''
        objectsPluginOle = [cPluginOle(ole, data, options.pluginoptions) for cPluginOle in pluginsOle]
        for oPluginOle in objectsPluginOle:
            oPluginOle.PreProcess()

        for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
            indicator = ' '
            macroPresent = False
            if options.info:
                moduleinfo = ' ' * 12
            else:
                moduleinfo = ''
            if options.unuseddata:
                lengthString = '            '
            else:
                lengthString = '       '
            if entry_type == 5:
                indicator = 'R'
            elif entry_type == 1:
                indicator = '.'
            elif entry_type == 2:
                if options.unuseddata:
                    lengthString = '%d(%d)' % (len(stream), sizeUnusedData)
                    lengthString = '%12s' % lengthString
                else:
                    lengthString = '%7d' % len(stream)
                moduleinfodata = dModuleinfo.get(''.join([c + '\x00' for c in fname[-1]]), None)
                if options.info and moduleinfodata != None:
                    moduleinfo = '%d+%d' % (moduleinfodata[6], len(stream) - moduleinfodata[6])
                    moduleinfo = '%12s' % moduleinfo
                macroPresent = FindCompression(stream) != -1
                if macroPresent:
                    returnCode = 2
                    if not SearchAndDecompressSub(stream)[0]:
                        indicator = 'E'
                    else:
                        indicator = 'M'
                        if MacrosContainsOnlyAttributesOrOptions(stream):
                            indicator = 'm'
                elif not macroPresent and moduleinfodata != None:
                    indicator = '!'
                elif OLE10HeaderPresent(stream):
                    indicator = 'O'
            index = '%s%d' % (prefix, counter)
            if not options.quiet:
                line = '%3s: %s %s%s %s' % (index, indicator, lengthString, moduleinfo, PrintableName(fname, orphan))
                if indicator.lower() == 'm' and options.vbadecompress:
                    streamForExtra = SearchAndDecompress(stream).encode()
                else:
                    streamForExtra = stream
                if options.calc:
                    line += ' %s' % hashlib.md5(streamForExtra).hexdigest()
                if options.extra.startswith('!'):
                    line = ''
                line += GenerateExtraInfo(options.extra, index, indicator, moduleinfo, PrintableName(fname, orphan), entry_metadata, streamForExtra)
                print(line)
            for cPlugin in plugins:
                try:
                    if cPlugin.macroOnly and macroPresent:
                        oPlugin = cPlugin(fname, SearchAndDecompress(stream), options.pluginoptions)
                    elif not cPlugin.macroOnly:
                        oPlugin = cPlugin(fname, stream, options.pluginoptions)
                    else:
                        oPlugin = None
                except Exception as e:
                    print('Error instantiating plugin: %s' % cPlugin.name)
                    if options.verbose:
                        raise e
                    return (returnCode, 0)
                if oPlugin != None:
                    result = oPlugin.Analyze()
                    if oPlugin.ran:
                        if options.quiet:
                            if oPlugin.indexQuiet:
                                if result != []:
                                    print('%3s: %s' % (index, MyRepr(result[0])))
                            elif type(result) == str or type(result) == bytes:
                                IfWIN32SetBinary(sys.stdout)
                                StdoutWriteChunked(result)
                            else:
                                for line in result:
                                    print(MyRepr(line))
                        else:
                            print('               Plugin: %s ' % oPlugin.name)
                            if type(result) == str:
                                print('                 use option -q to dump the following data')
                                print('                 ' + MyRepr(result))
                            else:
                                for line in result:
                                    print('                 ' + MyRepr(line))

            for oPluginOle in objectsPluginOle:
                oPluginOle.Process(fname, stream)

            counter += 1
            if options.yara != None:
                oDecoders = [cIdentity(stream, None)]
                for cDecoder in decoders:
                    try:
                        oDecoder = cDecoder(stream, options.decoderoptions)
                        oDecoders.append(oDecoder)
                    except Exception as e:
                        print('Error instantiating decoder: %s' % cDecoder.name)
                        if options.verbose:
                            raise e
                        return (returnCode, 0)
                for oDecoder in oDecoders:
                    while oDecoder.Available():
                        for result in rules.match(data=oDecoder.Decode(), externals={'streamname': PrintableName(fname), 'VBA': False}):
                            print('               YARA rule%s: %s' % (IFF(oDecoder.Name() == '', '', ' (stream decoder: %s)' % oDecoder.Name()), result.rule))
                            if options.yarastrings:
                                for stringdata in result.strings:
                                    print('               %06x %s:' % (stringdata[0], stringdata[1]))
                                    print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                                    print('                %s' % repr(stringdata[2]))
            if indicator.lower() == 'm':
                vbaConcatenate += SearchAndDecompress(stream) + '\n'

        if options.yara != None and vbaConcatenate != '':
            print('All VBA source code:')
            for result in rules.match(data=vbaConcatenate, externals={'streamname': '', 'VBA': True}):
                print('               YARA rule: %s' % result.rule)
                if options.yarastrings:
                    for stringdata in result.strings:
                        print('               %06x %s:' % (stringdata[0], stringdata[1]))
                        print('                %s' % binascii.hexlify(C2BIP3(stringdata[2])))
                        print('                %s' % repr(stringdata[2]))

        for oPluginOle in objectsPluginOle:
            oPluginOle.PostProcess()

    else:
        if len(decoders) > 1:
            print('Error: provide only one decoder when using option select')
            return (returnCode, 0)
        if options.decompress:
            DecompressFunction = HeuristicDecompress
        else:
            DecompressFunction = lambda x:x
        if options.dump:
            DumpFunction = lambda x:x
            IfWIN32SetBinary(sys.stdout)
        elif options.hexdump:
            DumpFunction = HexDump
        elif options.vbadecompress:
            if options.select == 'a':
                DumpFunction = lambda x: SearchAndDecompress(x, '')
            else:
                DumpFunction = SearchAndDecompress
        elif options.vbadecompressskipattributes:
            if options.select == 'a':
                DumpFunction = lambda x: SearchAndDecompress(x, '', True)
            else:
                DumpFunction = lambda x: SearchAndDecompress(x, skipAttributes=True)
        elif options.vbadecompresscorrupt:
            DumpFunction = lambda x: SearchAndDecompress(x, None)
        elif options.extract:
            DumpFunction = Extract
            IfWIN32SetBinary(sys.stdout)
        elif options.info:
            DumpFunction = Info
        elif options.translate != '':
            DumpFunction = Translate(options.translate)
        elif options.strings:
            DumpFunction = DumpFunctionStrings
        elif options.asciidumprle:
            DumpFunction = lambda x: HexAsciiDump(x, True)
        else:
            DumpFunction = HexAsciiDump

        counter = 1
        if options.select.endswith('c') or options.select.endswith('s'):
            selection = options.select[:-1]
            part = options.select[-1]
        else:
            selection = options.select
            part = ''
        for orphan, fname, entry_type, entry_metadata, stream, sizeUnusedData in OLEGetStreams(ole, options.storages, options.unuseddata):
            if selection == 'a' or ('%s%d' % (prefix, counter)) == selection.upper() or prefix == 'A' and str(counter) == selection or PrintableName(fname).lower() == selection.lower():
                StdoutWriteChunked(HeadTail(DumpFunction(DecompressFunction(DecodeFunction(decoders, options, CutData(SelectPart(stream, part, dModuleinfo.get(''.join([c + '\x00' for c in fname[-1]]), None)), options.cut)[0]))), options.headtail))
                selectionCounter += 1
                if selection != 'a':
                    break
            counter += 1

    return (returnCode, selectionCounter)

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
        return yara.compile(source=rule, externals={'streamname': '', 'VBA': False}), rule
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
        return yara.compile(filepaths=dFilepaths, externals={'streamname': '', 'VBA': False}), ','.join(dFilepaths.values())

def PrintWarningSelection(select, selectionCounter):
    if select != '' and selectionCounter == 0:
        print('Warning: no stream was selected with expression %s' % select)

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

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

def OLEDump(filename, options):
    returnCode = 0

    if filename != '' and not os.path.isfile(filename):
        print('Error: %s is not a file.' % filename)
        return returnCode

    global plugins
    global pluginsOle
    plugins = []
    pluginsOle = []
    LoadPlugins(options.plugins, options.plugindir, True)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    if options.raw:
        if filename == '':
            IfWIN32SetBinary(sys.stdin)
            if sys.version_info[0] > 2:
                data = sys.stdin.buffer.read()
            else:
                data = sys.stdin.read()
        else:
            data = File2String(filename)
        if options.vbadecompress:
            positions = FindAll(data, b'\x00Attribut\x00e ')
            vba = ''
            if options.vbadecompresscorrupt:
                for position in positions:
                    result = SearchAndDecompress(data[position - 3:], None, skipAttributes=options.vbadecompressskipattributes)
                    if result != None:
                        vba += result
            else:
                for position in positions:
                    result = SearchAndDecompress(data[position - 3:], skipAttributes=options.vbadecompressskipattributes) + '\n\n'
                    if result != None:
                        vba += result
            if options.plugins == '':
                print(vba)
                return returnCode
            else:
                data = vba
        for cPlugin in plugins:
            try:
                if cPlugin.macroOnly:
                    oPlugin = cPlugin(filename, data, options.pluginoptions)
                elif not cPlugin.macroOnly:
                    oPlugin = cPlugin(filename, data, options.pluginoptions)
                else:
                    oPlugin = None
            except Exception as e:
                print('Error instantiating plugin: %s' % cPlugin.name)
                if options.verbose:
                    raise e
                return returnCode
            if oPlugin != None:
                result = oPlugin.Analyze()
                if oPlugin.ran:
                    if options.quiet:
                        for line in result:
                            print(MyRepr(line))
                    else:
                        print('Plugin: %s ' % oPlugin.name)
                        for line in result:
                            print(' ' + MyRepr(line))
        return returnCode

    rules = None
    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            if sys.version >= '2.7.9':
                print("You can use PIP to install yara-python like this: pip install yara-python\npip is located in Python's Scripts folder.\n")
            return returnCode
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        if sys.version_info[0] > 2:
            oStringIO = DataIO(sys.stdin.buffer.read())
        else:
            oStringIO = DataIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = CreateZipFileObject(filename, 'r')
        try:
            oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(options.password))
        except NotImplementedError:
            print('This ZIP file is possibly not readable with module zipfile.\nTry installing module pyzipper: pip install pyzipper')
            return returnCode
        oStringIO = DataIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = DataIO(open(filename, 'rb').read())

    if options.find != '':
        filecontent = oStringIO.read()
        locations = FindAll(filecontent, OLEFILE_MAGIC)
        if len(locations) == 0:
            print('No embedded OLE files found')
        else:
            if options.find == 'l':
                print('Position of potential embedded OLE files:')
                for index, position in enumerate(locations):
                    print(' %d 0x%08x' % (index + 1, position))
            else:
                index = int(options.find)
                if index <= 0 or index > len(locations):
                    print('Wrong index, must be between 1 and %d' % len(locations))
                else:
                    ole = olefile.OleFileIO(DataIO(filecontent[locations[int(options.find) -  1]:]))
                    returnCode, selectionCounter = OLESub(ole, b'', '', rules, options)
                    PrintWarningSelection(options.select, selectionCounter)
                    ole.close()
    else:
        magic = oStringIO.read(6)
        oStringIO.seek(0)
        if magic[0:4] == OLEFILE_MAGIC:
            ole = olefile.OleFileIO(oStringIO)
            oStringIO.seek(0)
            returnCode, selectionCounter = OLESub(ole, oStringIO.read(), '', rules, options)
            PrintWarningSelection(options.select, selectionCounter)
            ole.close()
        elif magic[0:2] == b'PK':
            oZipfile = CreateZipFileObject(oStringIO, 'r')
            counter = 0
            selectionCounterTotal = 0
            oleFileFound = False
            OPCFound = False
            for info in oZipfile.infolist():
                oZipContent = oZipfile.open(info, 'r')
                content = oZipContent.read()
                if info.filename == '[Content_Types].xml':
                    OPCFound = True
                if content[0:4] == OLEFILE_MAGIC:
                    letter = chr(P23Ord('A') + counter)
                    counter += 1
                    if options.select == '':
                        if not options.quiet and not options.jsonoutput:
                            print('%s: %s' % (letter, info.filename))
                    ole = olefile.OleFileIO(DataIO(content))
                    returnCodeSub, selectionCounter = OLESub(ole, content, letter, rules, options)
                    returnCode = max(returnCode, returnCodeSub)
                    selectionCounterTotal += selectionCounter
                    oleFileFound = True
                    ole.close()
                oZipContent.close()
            if not oleFileFound:
                print('Warning: no OLE file was found inside this ZIP container%s' % IFF(OPCFound, ' (OPC)', ''))
            PrintWarningSelection(options.select, selectionCounterTotal)
            oZipfile.close()
        else:
            data = oStringIO.read()
            oStringIO.seek(0)
            if b'<?xml' in data and not b"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>" in data:
                try:
                    oXML = xml.dom.minidom.parse(oStringIO)
                except:
                    print('Error: parsing %s as XML.' % filename)
                    return -1
                counter = 0
                for oElement in oXML.getElementsByTagName('*'):
                    if oElement.firstChild and oElement.firstChild.nodeValue:
                        try:
                            data = binascii.a2b_base64(oElement.firstChild.nodeValue)
                        except binascii.Error:
                            data = ''
                        except UnicodeEncodeError:
                            data = ''
                        content = C2BIP3(data)
                        if content.startswith(ACTIVEMIME_MAGIC):
                            content = HeuristicZlibDecompress(content)
                        if content[0:4] == OLEFILE_MAGIC:
                            letter = chr(P23Ord('A') + counter)
                            counter += 1
                            if options.select == '':
                                if not options.quiet:
                                    nameValue = ''
                                    for key, value in oElement.attributes.items():
                                        if key.endswith(':name'):
                                            nameValue = value
                                            break
                                    print('%s: %s' % (letter, nameValue))
                            ole = olefile.OleFileIO(DataIO(content))
                            returnCodeSub, selectionCounter = OLESub(ole, content, letter, rules, options)
                            returnCode = max(returnCode, returnCodeSub)
                            PrintWarningSelection(options.select, selectionCounter)
                            ole.close()
            elif data.startswith(ACTIVEMIME_MAGIC):
                content = HeuristicZlibDecompress(data)
                if content[0:4] == OLEFILE_MAGIC:
                    ole = olefile.OleFileIO(DataIO(content))
                    returnCode, selectionCounter = OLESub(ole, content, '', rules, options)
                    PrintWarningSelection(options.select, selectionCounter)
                    ole.close()
            else:
                print('Error: %s is not a valid OLE file.' % filename)

    return returnCode

def OptionsEnvironmentVariables(options):
    if options.extra == '':
        options.extra = os.getenv('OLEDUMP_EXTRA', options.extra)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-S', '--strings', action='store_true', default=False, help='perform strings dump')
    oParser.add_option('-T', '--headtail', action='store_true', default=False, help='do head & tail')
    oParser.add_option('-v', '--vbadecompress', action='store_true', default=False, help='VBA decompression')
    oParser.add_option('--vbadecompressskipattributes', action='store_true', default=False, help='VBA decompression, skipping initial attributes')
    oParser.add_option('--vbadecompresscorrupt', action='store_true', default=False, help='VBA decompression, display beginning if corrupted')
    oParser.add_option('-r', '--raw', action='store_true', default=False, help='read raw file (use with options -v or -p')
    oParser.add_option('-t', '--translate', type=str, default='', help='string translation, like utf16 or .decode("utf8")')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='extract OLE embedded file')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    oParser.add_option('--plugindir', type=str, default='', help='directory for the plugin')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='only print output from plugins')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file, directory or #rule to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-M', '--metadata', action='store_true', default=False, help='Print metadata')
    oParser.add_option('-c', '--calc', action='store_true', default=False, help='Add extra calculated data to output, like hashes')
    oParser.add_option('--decompress', action='store_true', default=False, help='Search for compressed data in the stream and decompress it')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors and YARA rules')
    oParser.add_option('-C', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: OLEDUMP_EXTRA)')
    oParser.add_option('--storages', action='store_true', default=False, help='Include storages in report')
    oParser.add_option('-f', '--find', type=str, default='', help='Find D0CF11E0 MAGIC sequence (use l for listing, number for selecting)')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('-u', '--unuseddata', action='store_true', default=False, help='Include unused data after end of stream')
    oParser.add_option('--password', default=MALWARE_PASSWORD, help='The ZIP password to be used (default %s)' % MALWARE_PASSWORD)
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-C) is invalid: %s' % options.cut)
        return 0

    OptionsEnvironmentVariables(options)

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    elif len(args) == 0:
        return OLEDump('', options)
    else:
        return OLEDump(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
