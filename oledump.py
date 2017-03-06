#!/usr/bin/env python

__description__ = 'Analyze OLE files (Compound Binary Files)'
__author__ = 'Didier Stevens'
__version__ = '0.0.27'
__date__ = '2017/03/04'

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

Todo:
"""

import optparse
import sys
import math
import os
import zipfile
import cStringIO
import binascii
import xml.dom.minidom
import zlib
import hashlib
import textwrap
import re
import string

try:
    import dslsimulationdb
except:
    dslsimulationdb = None

try:
    import yara
except:
    pass

try:
    import olefile
except:
    print('This program requires module olefile.\nhttp://www.decalage.info/python/olefileio\n')
    if sys.version >= '2.7.9':
        print("You can use PIP to install olefile like this: pip install olefile\npip is located in Python's Scripts folder.\n")
    exit(-1)

dumplinelength = 16
MALWARE_PASSWORD = 'infected'
OLEFILE_MAGIC = '\xD0\xCF\x11\xE0'
ACTIVEMIME_MAGIC = 'ActiveMime'

def PrintManual():
    manual = '''
Manual:

oledump is a tool to analyze OLE files (also known as Compound File Binary). Many file formats are in fact OLE files, like Microsoft Office files, MSI files, ... Even the new Microsoft Office Open XML format uses OLE files for VBA macros.
oledump can analyze OLE files directly, or indirectly when then are contained in some form or other (like .docm, .xml, ...).

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
00000000: FE FF 00 00 05 01 02 00 00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00 01 00 00 00 02 D5 CD D5  .............i-i
00000020: 9C 2E 1B 10 93 97 08 00 2B 2C F9 AE 30 00 00 00  ........+,..0...
00000030: E4 00 00 00 09 00 00 00 01 00 00 00 50 00 00 00  ............P...
00000040: 0F 00 00 00 58 00 00 00 17 00 00 00 70 00 00 00  ....X.......p...
...

When selecting a stream, its content is shown as an ASCII dump (this can also be done with option -a).
Option -x produces a hexadecimal dump instead of an ASCII dump.

C:\Demo>oledump.py -s 1 -x Book1.xls
00000000: FE FF 00 00 05 01 02 00 00 00 00 00 00 00 00 00
00000010: 00 00 00 00 00 00 00 00 01 00 00 00 02 D5 CD D5
00000020: 9C 2E 1B 10 93 97 08 00 2B 2C F9 AE 30 00 00 00
00000030: E4 00 00 00 09 00 00 00 01 00 00 00 50 00 00 00
00000040: 0F 00 00 00 58 00 00 00 17 00 00 00 70 00 00 00
...

Option -d produces a raw dump of the content of the stream. This content can be redirected to a file, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls > content.bin

or it can be piped into another command, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls | pdfid.py -f

Option -C (--cut) allows for the partial selection of a stream. Use this option to "cut out" part of the stream.
The --cut option takes an argument to specify which section of bytes to select from the stream. This argument is composed of 2 terms separated by a colon (:), like this:
termA:termB
termA and termB can be:
- nothing (an empty string)
- a positive decimal number; example: 10
- an hexadecimal number (to be preceded by 0x); example: 0x10
- a case sensitive string to search for (surrounded by square brackets and single quotes); example: ['MZ']
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
Search string expressions (ASCII and hexadecimal) can be followed by an instance (a number equal to 1 or greater) to indicate which instance needs to be taken. For example, ['ABC']2 will search for the second instance of string 'ABC'. If this instance is not found, then nothing is selected.
Search string expressions (ASCII and hexadecimal) can be followed by an offset (+ or - a number) to add (or substract) an offset to the found instance. For example, ['ABC']+3 will search for the first instance of string 'ABC' and then select the bytes after ABC (+ 3).
Finally, search string expressions (ASCII and hexadecimal) can be followed by an instance and an offset.
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

Option -r can be used together with option -v to decompress a VBA macro stream that was extracted through some other mean than oledump. In such case, you provide the file that contains the compressed macro, instead of the OLE file.

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

To extract the embedded file, use option -e and redirect the output to a file like this:
C:\Demo>oledump.py -s 6 -e Book1-insert-object-calc-rol3.exe.xls > extracted.bin

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

oledump can scan the content of the streams with YARA rules (the YARA Python module must be installed). You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files. All streams are scanned with the provided YARA rules, you can not use option -s to select an individual stream.

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

The return code of oledump is 0, except when you use no options and the analyzed file contains macros. When macros are found, the return code is 2.
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

def PrintableName(fname):
    return repr('/'.join(fname))

def ParseTokenSequence(data):
    flags = ord(data[0])
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
    header = ord(compressedChunk[0]) + ord(compressedChunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flagCompressed = header & 0x8000
    data = compressedChunk[2:2 + size - 2]

    if flagCompressed == 0:
        return data, compressedChunk[size:]

    decompressedChunk = ''
    while len(data) != 0:
        tokens, data = ParseTokenSequence(data)
        for token in tokens:
            if len(token) == 1:
                decompressedChunk += token
            else:
                if decompressedChunk == '':
                    return None, None
                numberOfOffsetBits = OffsetBits(decompressedChunk)
                copyToken = ord(token[0]) + ord(token[1]) * 0x100
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

def Decompress(compressedData):
    if compressedData[0] != chr(1):
        return (False, None)
    remainder = compressedData[1:]
    decompressed = ''
    while len(remainder) != 0:
        decompressedChunk, remainder = DecompressChunk(remainder)
        if decompressedChunk == None:
            return (False, decompressed)
        decompressed += decompressedChunk
    return (True, decompressed.replace('\r\n', '\n'))

def FindCompression(data):
    searchString = '\x00Attribut'
    position = data.find(searchString)
    if position != -1 and data[position + len(searchString)] == 'e':
        position = -1
    return position

def SearchAndDecompressSub(data):
    position = FindCompression(data)
    if position == -1:
        return (False, '')
    else:
        compressedData = data[position - 3:]
    return Decompress(compressedData)

def SearchAndDecompress(data, ifError='Error: unable to decompress\n'):
    result, decompress = SearchAndDecompressSub(data)
    if result:
        return decompress
    elif ifError == None:
        return decompress
    else:
        return ifError

def ReadWORD(data):
    if len(data) < 2:
        return None, None
    return ord(data[0]) + ord(data[1]) *0x100, data[2:]

def ReadDWORD(data):
    if len(data) < 4:
        return None, None
    return ord(data[0]) + ord(data[1]) *0x100 + ord(data[2]) *0x10000 + ord(data[3]) *0x1000000, data[4:]

def ReadNullTerminatedString(data):
    position = data.find('\x00')
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
    return binascii.b2a_hex(data) + ' ' + ''.join([IFF(ord(c) >= 32, c, '.') for c in data])

def Info(data):
    result = ExtractOle10Native(data)
    if result == []:
        return 'Error: extraction failed'
    return 'String 1: %s\nString 2: %s\nString 3: %s\nSize embedded file: %d\nMD5 embedded file: %s\nMAGIC:  %s\nHeader: %s\n' % (result[0], result[1], result[2], len(result[3]), hashlib.md5(result[3]).hexdigest(), GenerateMAGIC(result[3][0:4]), GenerateMAGIC(result[3][0:16]))

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

def LoadPlugins(plugins, plugindir, verbose):
    if plugins == '':
        return

    if plugindir == '':
        scriptPath = os.path.dirname(sys.argv[0])
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

def LoadDecoders(decoders, decoderdir, verbose):
    if decoders == '':
        return

    if decoderdir == '':
        scriptPath = os.path.dirname(sys.argv[0])
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

def MacrosContainsOnlyAttributesOrOptions(stream):
    lines = SearchAndDecompress(stream).split('\n')
    for line in [line.strip() for line in lines]:
        if line != '' and not line.startswith('Attribute ') and not line == 'Option Explicit':
            return False
    return True

#https://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx
dCodepages = {
    037: 'IBM EBCDIC US-Canada',
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

def HeuristicDecompress(data):
    for position in FindAll(data, '\x78'):
        try:
            return zlib.decompress(data[position:])
        except:
            pass
    return data

CUTTERM_NOTHING = 0
CUTTERM_POSITION = 1
CUTTERM_FIND = 2
CUTTERM_LENGTH = 3

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
        dPrevalence[ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%f' % entropy

def ExtraInfoHEADHEX(data):
    return binascii.hexlify(data[:16])

def ExtraInfoHEADASCII(data):
    return ''.join([IFF(ord(b) >= 32, b, '.') for b in data[:16]])

def ExtraInfoTAILHEX(data):
    return binascii.hexlify(data[-16:])

def ExtraInfoTAILASCII(data):
    return ''.join([IFF(ord(b) >= 32, b, '.') for b in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[ord(char)] += 1
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
        dPrevalence[ord(char)] += 1
    sumValues, entropy, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def GenerateExtraInfo(extra, index, indicator, name, stream):
    if extra == '':
        return ''
    if extra.startswith('!'):
        extra = extra[1:]
        prefix = ''
    else:
        prefix = ' '
    if indicator == ' ':
        indicator = ''
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

def OLESub(ole, prefix, rules, options):
    global plugins
    global decoders

    returnCode = 0

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
        print('Properties DocumentSummaryInformation:')
        for attribute in metadata.DOCSUM_ATTRIBS:
            value = getattr(metadata, attribute)
            if value != None:
                if attribute == 'codepage_doc':
                    print(' %s: %s %s' % (attribute, value, LookupCodepage(value)))
                else:
                    print(' %s: %s' % (attribute, value))
        return returnCode

    if options.select == '':
        counter = 1
        vbaConcatenate = ''
        for fname in ole.listdir():
            stream = None
            indicator = ' '
            macroPresent = False
            lengthString = '      '
            if ole.get_type(fname) == 1:
                indicator = '.'
            elif ole.get_type(fname) == 2:
                stream = ole.openstream(fname).read()
                lengthString = '%7d' % len(stream)
                macroPresent = FindCompression(stream) != -1
                if macroPresent:
                    returnCode = 2
                    if not SearchAndDecompressSub(stream)[0]:
                        indicator = 'E'
                    else:
                        indicator = 'M'
                        if MacrosContainsOnlyAttributesOrOptions(stream):
                            indicator = 'm'
                elif OLE10HeaderPresent(stream):
                    indicator = 'O'
            if not options.quiet:
                index = '%s%d' % (prefix, counter)
                line = '%3s: %s %s %s' % (index, indicator, lengthString, PrintableName(fname))
                if indicator.lower() == 'm' and options.vbadecompress:
                    streamForExtra = SearchAndDecompress(stream)
                else:
                    streamForExtra = stream
                if options.calc:
                    line += ' %s' % hashlib.md5(streamForExtra).hexdigest()
                if options.extra.startswith('!'):
                    line = ''
                line += GenerateExtraInfo(options.extra, index, indicator, PrintableName(fname), streamForExtra)
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
                    return returnCode
                if oPlugin != None:
                    result = oPlugin.Analyze()
                    if oPlugin.ran:
                        if options.quiet:
                            for line in result:
                                print(MyRepr(line))
                        else:
                            print('               Plugin: %s ' % oPlugin.name)
                            for line in result:
                                print('                 ' + MyRepr(line))
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
                        return returnCode
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
    else:
        if len(decoders) > 1:
            print('Error: provide only one decoder when using option select')
            return returnCode
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
        elif options.vbadecompresscorrupt:
            DumpFunction = lambda x: SearchAndDecompress(x, None)
        elif options.extract:
            DumpFunction = Extract
            IfWIN32SetBinary(sys.stdout)
        elif options.info:
            DumpFunction = Info
        else:
            DumpFunction = HexAsciiDump
        counter = 1
        for fname in ole.listdir():
            if options.select == 'a' or ('%s%d' % (prefix, counter)) == options.select:
                StdoutWriteChunked(DumpFunction(DecompressFunction(DecodeFunction(decoders, options, CutData(ole.openstream(fname).read(), options.cut)))))
                if options.select != 'a':
                    break
            counter += 1

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
    return yara.compile(filepaths=dFilepaths, externals={'streamname': '', 'VBA': False})

def FilenameInSimulations(filename):
    if dslsimulationdb == None:
        return False
    return filename in dslsimulationdb.dSimulations

def OLEDump(filename, options):
    returnCode = 0

    if filename != '' and not FilenameInSimulations(filename) and not os.path.isfile(filename):
        print('Error: %s is not a file.' % filename)
        return returnCode

    global plugins
    plugins = []
    LoadPlugins(options.plugins, options.plugindir, True)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    if options.raw:
        if filename == '':
            IfWIN32SetBinary(sys.stdin)
            data = sys.stdin.read()
        else:
            data = File2String(filename)
        if options.vbadecompress:
            if options.vbadecompresscorrupt:
                vba = SearchAndDecompress(data, None)
            else:
                vba = SearchAndDecompress(data)
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
            return returnCode
        rules = YARACompile(options.yara)

    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif FilenameInSimulations(filename):
        oZipfile = zipfile.ZipFile(dslsimulationdb.GetSimulation(filename), 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        zipContent = oZipContent.read()
        if zipContent.startswith('Neut'):
            zipContent = OLEFILE_MAGIC + zipContent[4:]
        oStringIO = cStringIO.StringIO(zipContent)
        oZipContent.close()
        oZipfile.close()
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    magic = oStringIO.read(6)
    oStringIO.seek(0)
    if magic[0:4] == OLEFILE_MAGIC:
        ole = olefile.OleFileIO(oStringIO)
        returnCode = OLESub(ole, '', rules, options)
        ole.close()
    elif magic[0:2] == 'PK':
        oZipfile = zipfile.ZipFile(oStringIO, 'r')
        counter = 0
        for info in oZipfile.infolist():
            oZipContent = oZipfile.open(info, 'r')
            content = oZipContent.read()
            if content[0:4] == OLEFILE_MAGIC:
                letter = chr(ord('A') + counter)
                counter += 1
                if options.select == '':
                    if not options.quiet:
                        print('%s: %s' % (letter, info.filename))
                ole = olefile.OleFileIO(cStringIO.StringIO(content))
                returnCode = OLESub(ole, letter, rules, options)
                ole.close()
            oZipContent.close()
        oZipfile.close()
    else:
        data = oStringIO.read()
        oStringIO.seek(0)
        if '<?xml' in data:
            oXML = xml.dom.minidom.parse(oStringIO)
            counter = 0
            for oElement in oXML.getElementsByTagName('*'):
                if oElement.firstChild and oElement.firstChild.nodeValue:
                    try:
                        data = binascii.a2b_base64(oElement.firstChild.nodeValue)
                    except binascii.Error:
                        data = ''
                    except UnicodeEncodeError:
                        data = ''
                    content = data
                    if content.startswith(ACTIVEMIME_MAGIC):
                        content = HeuristicDecompress(content)
                    if content[0:4] == OLEFILE_MAGIC:
                        letter = chr(ord('A') + counter)
                        counter += 1
                        if options.select == '':
                            if not options.quiet:
                                nameValue = ''
                                for key, value in oElement.attributes.items():
                                    if key.endswith(':name'):
                                        nameValue = value
                                        break
                                print('%s: %s' % (letter, nameValue))
                        ole = olefile.OleFileIO(cStringIO.StringIO(content))
                        returnCode = OLESub(ole, letter, rules, options)
                        ole.close()
        elif data.startswith(ACTIVEMIME_MAGIC):
            content = HeuristicDecompress(data)
            if content[0:4] == OLEFILE_MAGIC:
                ole = olefile.OleFileIO(cStringIO.StringIO(content))
                returnCode = OLESub(ole, '', rules, options)
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
    oParser.add_option('-v', '--vbadecompress', action='store_true', default=False, help='VBA decompression')
    oParser.add_option('--vbadecompresscorrupt', action='store_true', default=False, help='VBA decompression, display beginning if corrupted')
    oParser.add_option('-r', '--raw', action='store_true', default=False, help='read raw file (use with options -v or -p')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='extract OLE embedded file')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    oParser.add_option('--plugindir', type=str, default='', help='directory for the plugin')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='only print output from plugins')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file or directory to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-M', '--metadata', action='store_true', default=False, help='Print metadata')
    oParser.add_option('-c', '--calc', action='store_true', default=False, help='Add extra calculated data to output, like hashes')
    oParser.add_option('--decompress', action='store_true', default=False, help='Search for compressed data in the stream and decompress it')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-C', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: OLEDUMP_EXTRA)')
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
