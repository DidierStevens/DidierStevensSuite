#!/usr/bin/env python

__description__ = 'ZIP dump utility'
__author__ = 'Didier Stevens'
__version__ = '0.0.21'
__date__ = '2020/11/21'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/02/01: start
  2014/04/30: added timestamp
  2014/10/07: added magic values and metadata; added option dumpall, hexdumpall and asciidumpall
  2014/10/09: refactoring, added option extra
  2014/10/13: fixed whitespace counter bug; -o bug
  2014/10/26: refactoring
  2014/11/09: added option -p
  2014/12/21: 0.0.2: Added YARA support; added decoders
  2015/01/08: 0.0.3: Added support for multiple YARA rule files
  2015/02/09: Added option yarastrings
  2015/06/08: Fix HexAsciiDump
  2015/07/21: filename = '*'
  2015/09/12: if the ZIP file contains a single ZIP file, then the contained ZIP file is dumped; added --cut
  2015/09/13: added option -r and -z
  2015/09/22: added --man
  2015/09/29: bug fixes
  2015/11/17: added support for :-number in --cut option; added -E option
  2016/05/26: refactoring and man
  2016/05/29: continue man, updated cut option
  2016/11/15: 0.0.4: Added support ZIP comment
  2016/11/16: added Unique bytes
  2017/01/29: 0.0.5: added # for option extra
  2017/05/02: 0.0.6: added options --passwordfile and --passwordfilestop
  2017/05/20: 0.0.7: added internal password list
  2017/05/21: 0.0.8: added extra exception DictionaryAttack
  2017/07/02: 0.0.9: added # support for option -y
  2017/07/11: 0.0.10: added option --yarastringsraw
  2017/07/18: 0.0.11: added #s# and #q# support for option -y
  2018/06/25: 0.0.12: added option -t
  2018/07/01: 0.0.13: added option --jsonoutput
  2018/07/07: 0.0.14: updated to version 2 of jsonoutput
  2018/12/15: 0.0.15: updated help
  2019/12/26: 0.0.16: added option -f and started Python 3 support
  2019/12/27: continue
  2020/01/05: 0.0.17: temporary bugfix in ZIPFind for reversed ZIP files
  2020/04/05: handle incomplete EOCD record
  2020/04/13: 0.0.18 added option info
  2020/04/29: 0.0.19 added support for AES with pyzipper
  2020/07/23: 0.0.20 added PK record data descriptor (PK 07 08)
  2020/08/16: 0.0.21 Python 3 fixes
  2020/10/21: Python 3 fix in cBinaryFile
  2020/11/21: Python 3 fix extra info

Todo:
"""

import optparse
import hashlib
import signal
import sys
import os
import string
import math
import binascii
import re
import textwrap
import operator
import time
import gzip
import zlib
import codecs
import json
import struct
try:
    import pyzipper as zipfile
except ImportError:
    import zipfile
try:
    import yara
except:
    pass
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO

QUOTE = '"'

def PrintManual():
    manual = '''
Manual:

zipdump is a tool to analyze ZIP files.

It uses built-in Python module zipfile, unless module pyzipper is installed. Module pyzipper adds AES support, and can be installed with pip (Python 3 only).

The ZIP file can be provided as an argument, via stdin (piping) and it may also be contained in a (password protected) ZIP file.

When providing zipdump with a file to analyze, it will report on the content of the ZIP file, like in this example:
C:\Demo>zipdump.py example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26
    2 readme.txt           0 2015-11-24 19:40:12

The first column, Index, is an index that zipdump assigns to each file inside the ZIP file. You can use it with option -s (select) to select a file for further analysis.
Filename is the filename of the contained file.
Encrypted is a flag indicating if the file is encrypted (1) or not (0).
And the last column (Timestamp) is the timestamp of the file inside the archive.

Option -s takes the index number or the filename to select a file.

By default, the separator used to delimit columns is the space character. When the default separator is used, padding is added to lign up the columns. Another separator character can be selected with option -S. No padding is used when the separator is provided (even if it is the space character).
C:\Demo>zipdump.py -S ; example.zip
Index;Filename;Encrypted;Timestamp;
1;Dialog42.exe;0;2012-02-25 12:08:26;
2;readme.txt;0;2015-11-24 19:40:12;

When a file is selected, the properties of this file are displayed:
C:\Demo>zipdump.py -s 1 example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26

The content of the selected file can also be dumped.
Use option -x to perform an hexdump:
C:\Demo>zipdump.py -s 1 -x example.zip
4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
...

Use option -a to perform an ascii/hexdump:
C:\Demo>zipdump.py -s 1 -a example.zip
00000000: 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00  MZP.............
00000010: B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00  +.......@.......
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...

Use option -d to perform a raw dump:
C:\Demo>zipdump.py -s 2 -d example.zip
test

A raw dump is useful to pipe the output into another command:
C:\Demo>zipdump.py -s 1 -d example.zip | pecheck.py
PE check for '':
Entropy: 6.425034 (Min=0.0, Max=8.0)
MD5     hash: 9b7f8260724e2cb643ad0729ec995b40
...

If the dump needs to be processed by a string codec, like utf16, use option -t instead of -d and provide the codec:
C:\Demo>zipdump.py -s 1 -t utf16 example.zip
You can also provide a Python string expression, like .decode('utf16').encode('utf8'). Remark that this uses the Python eval function with untrusted input, so be careful, it can be used for code injection.

When options -x, -a or -d are used without selecting a file (option -s), the first file in the ZIP file is selected and dumped.
When options -X, -A or -D are used without selecting a file (option -s), all files in the ZIP file are selected and dumped.

The output produced by zipdump.py can de written to a file with option -o.

If the ZIP file is password protected, zipdump.py will try with password 'infected'. Option -p can be used to provide a different password to open the ZIP file. To provide a list of passwords to try,
use option -P with the name of the file containing passwords to try (dictionary attack). This file can be a text file or a gzip compressed text file. The password file is completely read into memory before the dictionary attack is executed.
After the dictionary attack, the selected commands (via other options) are executed.
Example:
C:\Demo>zipdump.py -P passwords.txt -s 1 -a password-protected.zip
00000000: 73 65 63 72 65 74 20 74 65 78 74                 secret text

To perform just a dictionary attack, without additional commands, use option --passwordfilestop. This option will produce progress output, like this:
C:\Demo>zipdump.py --passwordfilestop rockyou.txt.gz secret.zip
Passwords:    10000 0.07% p/s: 7727 ETC: 2017/05/01 20:18:50
Passwords:    20000 0.14% p/s: 7883 ETC: 2017/05/01 20:18:13
Passwords:    30000 0.21% p/s: 7947 ETC: 2017/05/01 20:17:58
Passwords:    40000 0.28% p/s: 7964 ETC: 2017/05/01 20:17:54
Password: loveyoubaby

zipdump also has an internal password list (a few thousand passwords), that can be used by providing filename . (a single dot) to options -P and --passwordfilestop.
Example:
C:\Demo>zipdump.py --passwordfilestop . secret.zip
Password: letmein

If the ZIP file contains a single ZIP file, the contained ZIP file will be considered to be the ZIP file to analyze. To prevent this, use option -r. Option -r handles the contained ZIP file as a regular file.

Option -z can be used to include the name of the zipfile in the report:
C:\Demo>zipdump.py -z -S ; example.zip
Index;Zipfilename;Filename;Encrypted;Timestamp;
1;example.zip;Dialog42.exe;0;2012-02-25 12:08:26;
2;example.zip;readme.txt;0;2015-11-24 19:40:12;

This can be useful when reports of many ZIP files are merged together.

Option -e extends the amount of information reported:
C:\Demo>zipdump.py -e example.zip
Index Filename     Encrypted Timestamp           MD5                              Filesize Entropy       Unique bytes Magic HEX Magic ASCII Null bytes Control bytes Whitespace bytes Printable bytes High bytes
    1 Dialog42.exe         0 2012-02-25 12:08:26 9b7f8260724e2cb643ad0729ec995b40    58120 6.42503434625          256 4d5a5000  MZP.             13014          6403             1678           19366      17659
    2 readme.txt           0 2015-11-24 19:40:12 098f6bcd4621d373cade4e832627b4f6        4 1.5                      3  74657374 test                 0             0                0               4          0

Columns MD5, Filesize and Entropy should be self-explanatory.
Unique bytes counts the number of unique, different byte values contained in the file.
The Magic columns (HEX and ASCII) report the first 4 bytes of the file.
The remaining columns provide more statistical data about the contained file. They count the number of bytes of a particular type found inside the contained file. The byte types are: null bytes, control bytes, whitespace, printable bytes and high bytes.

If you need other data than displayed by option -e, use option -E (extra). This option takes a parameter describing the extra data that needs to be calculated and displayed for each file. The following variables are defined:
  %INDEX%: the index of the file
  %ZIPFILENAME%: the filename of the ZIP container
  %FILENAME%: the filename of the contained file
  %ENCRYPTED%: encrypted indicator
  %TIMESTAMP%: timestamp
  %LENGTH%': the length of the file
  %MD5%: calculates MD5 hash
  %SHA1%: calculates SHA1 hash
  %SHA256%: calculates SHA256 hash
  %ENTROPY%: calculates entropy
  %HEADHEX%: display first 20 bytes of the file as hexadecimal
  %HEADASCII%: display first 20 bytes of the file as ASCII
  %TAILHEX%: display last 20 bytes of the file as hexadecimal
  %TAILASCII%: display last 20 bytes of the file as ASCII
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

Example adding the SHA256 hash to the report:
C:\Demo>zipdump.py -E "%SHA256%" example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26 0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
    2 readme.txt           0 2015-11-24 19:40:12 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

The parameter for -E may contain other text than the variables, which will be printed. Escape characters \\n and \\t are supported.
Example displaying the MD5 and SHA256 hash per file, separated by a - character:
C:\Demo>zipdump.py -E "%MD5%-%SHA256%" example.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26 9b7f8260724e2cb643ad0729ec995b40-0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
    2 readme.txt           0 2015-11-24 19:40:12 098f6bcd4621d373cade4e832627b4f6-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

If the extra parameter starts with !, then it replaces the complete output line (in stead of being appended to the output line).
Example:
C:\Demo>zipdump.py -E "!%FILENAME%;%SHA256%" example.zip
Dialog42.exe;0a391054e50a4808553466263c9c3b63e895be02c957dbb957da3ba96670cf34
readme.txt;9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

If the extra parameter starts with #, then it produces a summary of output.
Example:
C:\Demo>zipdump.py -E "#%HEADASCII%;%HEADHEX%" Book1.xlsm
   1: --..............;d0cf11e0a1b11ae10000000000000000
   1: <xml xmlns:v="ur;3c786d6c20786d6c6e733a763d227572
  12: <?xml version="1;3c3f786d6c2076657273696f6e3d2231

To include extra data with each use of zipdump, define environment variable ZIPDUMP_EXTRA with the parameter that should be passed to -E. When environment variable ZIPDUMP_EXTRA is defined, option -E can be ommited. When option -E is used together with environment variable ZIPDUMP_EXTRA, the parameter of option -E is used and the environment variable is ignored.

zipdump supports YARA rules. Installation of the YARA Python module is not mandatory if you don't use YARA rules.
You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files.
Or you can provide the YARA rule with the option value if it starts with # (literal), #s# (string), #q# (quote), #h# (hexadecimal) or #b# (base64). Example: -y "#rule demo {strings: $a=\"demo\" condition: $a}"
Using #s#demo will instruct zipdump to generate a rule to search for string demo (rule string {strings: $a = "demo" ascii wide nocase condition: $a) and use that rule.
All files inside the ZIP file are scanned with the provided YARA rules, you can not use option -s to select an individual file.

Example:
C:\Demo>zipdump.py -y contains_pe_file.yara example.zip
Index Filename     Decoder YARA namespace        YARA rule
    1 Dialog42.exe         contains_pe_file.yara Contains_PE_File

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) inside ZIP files. The rule triggered for file 1, because it contains an EXE file.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
C:\Demo>zipdump.py -y contains_pe_file.yara --yarastrings example.zip
Index Filename     Decoder YARA namespace        YARA rule
    1 Dialog42.exe         contains_pe_file.yara Contains_PE_File 000000 $a 4d5a 'MZ'

Use option --yarastringsraw to see only the matched strings, and nothing more.

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

To deal with encoded files, zipdump supports decoders. A decoder is a type of plugin, that will bruteforce a type of encoding on each file. For example, decoder_xor1 will encode each file via XOR and a key of 1 byte. So effectively, 256 different encodings of the file will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
C:\Demo>zipdump.py -y contains_pe_file.yara -C decoder_xor1 example.zip
Index Filename            Decoder             YARA namespace        YARA rule
    1 Dialog42.exe                            contains_pe_file.yara Contains_PE_File
    3 Dialog42.exe.XORx14 XOR 1 byte key 0x14 contains_pe_file.yara Contains_PE_File

The YARA rule triggers on file 3. It contains a PE file encoded via XORing each byte with key 0x14.

You can specify more than one decoder separated by a comma ,.
C:\Demo>zipdump.py -y contains_pe_file.yara -C decoder_xor1,decoder_rol1,decoder_add1 example.zip

Some decoders take options, to be provided with option --decoderoptions.

Use option -v to have verbose error messages when debugging your decoders.

With option -j, zipdump will output the content of the ZIP file as a JSON object that can be piped into other tools that support this JSON format.

When a file contains more than one ZIP file, option -f (find) can be used to detect this and select distinct ZIP files.

We will use double.zip, it is a PoC ZIP file: it is the concatenation of 2 ZIP files, the first ZIP file contains a single text file, the second ZIP file contains a single EXE file.
When zipdump is used to analyse this file, only the second ZIP file (e.g. last) is analyzed:

C:\Demo>zipdump.py double.zip
Index Filename     Encrypted Timestamp
    1 Dialog42.exe         0 2012-02-25 12:08:26

To detect the presence of multiple ZIP files, use option -f with value list (or letter l, initial of list), like this:

C:\Demo>zipdump.py -f list double.zip
     0x00000000 PK0304 fil b'file.txt'
     0x000002bf PK0102 dir b'file.txt'
   1 0x00000319 PK0506 end
     0x0000032f PK0304 fil b'Dialog42.exe'
     0x000078ef PK0102 dir b'Dialog42.exe'
   2 0x0000794d PK0506 end

Option "-f list" lists all PK records it finds of the following type:
  PK0304 local file header
  PK0102 central directory header
  PK0506 end of central directory

The presence of more than one "end of central directory" record indicates the presence of multiple ZIP files. Compare the result above for double.zip with a single ZIP file:

C:\Demo>zipdump.py -f list example.zip
     0x00000000 PK0304 fil b'Dialog42.exe'
     0x000075c0 PK0102 dir b'Dialog42.exe'
   1 0x0000761e PK0506 end

Every "end of central directory" record is prefixed by an index, that can be used to select that particular ZIP file for further analysis, using option -f like this (option "-f 1", index number 1):

C:\Demo>zipdump.py -f 1 double.zip
Index Filename Encrypted Timestamp
    1 file.txt         0 2019-12-03 22:55:46

Option -f can be combined with all other zipdump options, to further analyze the selected ZIP file. Example:

C:\Demo>zipdump.py -f 1 -s 1 -a double.zip | head
00000000: 50 6F 72 74 74 69 74 6F  72 20 6C 75 63 74 75 73  Porttitor luctus
00000010: 20 72 69 73 75 73 20 6E  69 73 69 20 6F 64 69 6F   risus nisi odio
00000020: 20 73 63 65 6C 65 72 69  73 71 75 65 20 70 6F 73   scelerisque pos
00000030: 75 65 72 65 20 6E 75 6C  6C 61 20 65 6C 65 69 66  uere nulla eleif
00000040: 65 6E 64 20 63 6F 6E 73  65 63 74 65 74 75 72 20  end consectetur
00000050: 6E 69 73 6C 20 74 65 6D  70 6F 72 20 73 61 67 69  nisl tempor sagi
00000060: 74 74 69 73 20 63 75 72  73 75 73 20 65 67 65 73  ttis cursus eges
00000070: 74 61 73 20 64 6F 6E 65  63 20 6E 61 74 6F 71 75  tas donec natoqu
00000080: 65 20 64 69 67 6E 69 73  73 69 6D 20 65 74 20 6A  e dignissim et j
00000090: 75 73 74 6F 20 74 69 6E  63 69 64 75 6E 74 20 75  usto tincidunt u

Option -i can be used together with option -f to provide info about the selected end-of-central-directory record (in stead of analyzing the ZIP file). Example:

C:\Demo>zipdump.py -f 1 -i sample.vir
EOCD (End Of Central Directory) record: PK\\x05\\x06
 Disk number field: 0
 Start disk number field: 0
 Entries on disk field: 15
 Entries in directory field: 15
 Directory size field: 975
 Directory offset field: 87903 (0x0001575f)
 Incomplete comment length field, missing 1 byte(s)
00000000: 00

If data precedes the first record, or succeeds the last record, an entry with index p (prefix) and/or index s (suffix) will be included in the list of records:

C:\Demo>zipdump.py -f list prefix-double.zip
   p 0x00000000 data 0:58120l
     0x0000e308 PK0304 fil b'file.txt'
     0x0000e5c7 PK0102 dir b'file.txt'
   1 0x0000e621 PK0506 end
     0x0000e637 PK0304 fil b'Dialog42.exe'
     0x00015bf7 PK0102 dir b'Dialog42.exe'
   2 0x00015c55 PK0506 end

C:\Demo>zipdump.py -f list double-suffix.zip
     0x00000000 PK0304 fil b'file.txt'
     0x000002bf PK0102 dir b'file.txt'
   1 0x00000319 PK0506 end
     0x0000032f PK0304 fil b'Dialog42.exe'
     0x000078ef PK0102 dir b'Dialog42.exe'
   2 0x0000794d PK0506 end
   s 0x00007963 data 31075:58120l

When p or s is selected with option -f, the selected data is dumped according to the dump flags (-d, -a, -x, -t).

Option -c (--cut) allows for the partial selection of a file. Use this option to "cut out" part of the file.
The --cut option takes an argument to specify which section of bytes to select from the file. This argument is composed of 2 terms separated by a colon (:), like this:
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
This argument can be used to dump the first 256 bytes of a PE file located inside the file: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the file: [d0cf11e0]:
When this option is not used, the complete file is selected.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 78))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d/%02d/%02d %02d:%02d:%02d' % time.localtime(epoch)[0:6]

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def Print(line, f):
    if f == None:
        print(line)
    else:
        f.write(line +'\n')

dumplinelength = 16

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

def File2Strings(filename):
    try:
         if os.path.splitext(filename)[1].lower() == '.gz':
             f = gzip.GzipFile(filename, 'rb')
         else:
             f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n\r'), f.readlines())
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

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

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
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule)
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
        return yara.compile(filepaths=dFilepaths)

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

    def HexAsciiDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        asciiDump = ''
        for i, b in enumerate(self.data):
            b = self.C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
                hexDump = '%08X:' % (i + self.offset)
                asciiDump = ''
            if i % self.dumplinelength == self.dumplinelength / 2:
                hexDump += ' '
            hexDump += ' %02X' % b
            asciiDump += IFF(b >= 32 and b < 127, chr(b), '.')
        oDumpStream.Addline(self.CombineHexAscii(hexDump, asciiDump))
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

def HexAsciiDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump()

def Translate(expression):
    try:
        codecs.lookup(expression)
        command = '.decode("%s")' % expression
    except LookupError:
        command = expression
    return lambda x: eval('x' + command)

#-BEGINCODE cBinaryFile------------------------------------------------------------------------------
#import random
#import binascii
#import zipfile
#import gzip
#import sys
#if sys.version_info[0] >= 3:
#    from io import BytesIO as DataIO
#else:
#    from cStringIO import StringIO as DataIO

def LoremIpsumSentence(minimum, maximum):
    words = ['lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'etiam', 'tortor', 'metus', 'cursus', 'sed', 'sollicitudin', 'ac', 'sagittis', 'eget', 'massa', 'praesent', 'sem', 'fermentum', 'dignissim', 'in', 'vel', 'augue', 'scelerisque', 'auctor', 'libero', 'nam', 'a', 'gravida', 'odio', 'duis', 'vestibulum', 'vulputate', 'quam', 'nec', 'cras', 'nibh', 'feugiat', 'ut', 'vitae', 'ornare', 'justo', 'orci', 'varius', 'natoque', 'penatibus', 'et', 'magnis', 'dis', 'parturient', 'montes', 'nascetur', 'ridiculus', 'mus', 'curabitur', 'nisl', 'egestas', 'urna', 'iaculis', 'lectus', 'maecenas', 'ultrices', 'velit', 'eu', 'porta', 'hac', 'habitasse', 'platea', 'dictumst', 'integer', 'id', 'commodo', 'mauris', 'interdum', 'malesuada', 'fames', 'ante', 'primis', 'faucibus', 'accumsan', 'pharetra', 'aliquam', 'nunc', 'at', 'est', 'non', 'leo', 'nulla', 'sodales', 'porttitor', 'facilisis', 'aenean', 'condimentum', 'rutrum', 'facilisi', 'tincidunt', 'laoreet', 'ultricies', 'neque', 'diam', 'euismod', 'consequat', 'tempor', 'elementum', 'lobortis', 'erat', 'ligula', 'risus', 'donec', 'phasellus', 'quisque', 'vivamus', 'pellentesque', 'tristique', 'venenatis', 'purus', 'mi', 'dictum', 'posuere', 'fringilla', 'quis', 'magna', 'pretium', 'felis', 'pulvinar', 'lacinia', 'proin', 'viverra', 'lacus', 'suscipit', 'aliquet', 'dui', 'molestie', 'dapibus', 'mollis', 'suspendisse', 'sapien', 'blandit', 'morbi', 'tellus', 'enim', 'maximus', 'semper', 'arcu', 'bibendum', 'convallis', 'hendrerit', 'imperdiet', 'finibus', 'fusce', 'congue', 'ullamcorper', 'placerat', 'nullam', 'eros', 'habitant', 'senectus', 'netus', 'turpis', 'luctus', 'volutpat', 'rhoncus', 'mattis', 'nisi', 'ex', 'tempus', 'eleifend', 'vehicula', 'class', 'aptent', 'taciti', 'sociosqu', 'ad', 'litora', 'torquent', 'per', 'conubia', 'nostra', 'inceptos', 'himenaeos']
    sample = random.sample(words, random.randint(minimum, maximum))
    sample[0] = sample[0].capitalize()
    return ' '.join(sample) + '.'

def LoremIpsum(sentences):
    return ' '.join([LoremIpsumSentence(15, 30) for i in range(sentences)])

STATE_START = 0
STATE_IDENTIFIER = 1
STATE_STRING = 2
STATE_SPECIAL_CHAR = 3
STATE_ERROR = 4

FUNCTIONNAME_REPEAT = 'repeat'
FUNCTIONNAME_RANDOM = 'random'
FUNCTIONNAME_CHR = 'chr'
FUNCTIONNAME_LOREMIPSUM = 'loremipsum'

def Tokenize(expression):
    result = []
    token = ''
    state = STATE_START
    while expression != '':
        char = expression[0]
        expression = expression[1:]
        if char == "'":
            if state == STATE_START:
                state = STATE_STRING
            elif state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                state = STATE_STRING
                token = ''
            elif state == STATE_STRING:
                result.append([STATE_STRING, token])
                state = STATE_START
                token = ''
        elif char >= '0' and char <= '9' or char.lower() >= 'a' and char.lower() <= 'z':
            if state == STATE_START:
                token = char
                state = STATE_IDENTIFIER
            else:
                token += char
        elif char == ' ':
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ''
                state = STATE_START
            elif state == STATE_STRING:
                token += char
        else:
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ''
                state = STATE_START
                result.append([STATE_SPECIAL_CHAR, char])
            elif state == STATE_STRING:
                token += char
            else:
                result.append([STATE_SPECIAL_CHAR, char])
                token = ''
    if state == STATE_IDENTIFIER:
        result.append([state, token])
    elif state == STATE_STRING:
        result = [[STATE_ERROR, 'Error: string not closed', token]]
    return result

def ParseFunction(tokens):
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    if tokens[0][0] == STATE_STRING or tokens[0][0] == STATE_IDENTIFIER and tokens[0][1].startswith('0x'):
        return [[FUNCTIONNAME_REPEAT, [[STATE_IDENTIFIER, '1'], tokens[0]]], tokens[1:]]
    if tokens[0][0] != STATE_IDENTIFIER:
        print('Parsing error')
        return None, tokens
    function = tokens[0][1]
    tokens = tokens[1:]
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != '(':
        print('Parsing error')
        return None, tokens
    tokens = tokens[1:]
    if len(tokens) == 0:
        print('Parsing error')
        return None, tokens
    arguments = []
    while True:
        if tokens[0][0] != STATE_IDENTIFIER and tokens[0][0] != STATE_STRING:
            print('Parsing error')
            return None, tokens
        arguments.append(tokens[0])
        tokens = tokens[1:]
        if len(tokens) == 0:
            print('Parsing error')
            return None, tokens
        if tokens[0][0] != STATE_SPECIAL_CHAR or (tokens[0][1] != ',' and tokens[0][1] != ')'):
            print('Parsing error')
            return None, tokens
        if tokens[0][0] == STATE_SPECIAL_CHAR and tokens[0][1] == ')':
            tokens = tokens[1:]
            break
        tokens = tokens[1:]
        if len(tokens) == 0:
            print('Parsing error')
            return None, tokens
    return [[function, arguments], tokens]

def Parse(expression):
    tokens = Tokenize(expression)
    if len(tokens) == 0:
        print('Parsing error')
        return None
    if tokens[0][0] == STATE_ERROR:
        print(tokens[0][1])
        print(tokens[0][2])
        print(expression)
        return None
    functioncalls = []
    while True:
        functioncall, tokens = ParseFunction(tokens)
        if functioncall == None:
            return None
        functioncalls.append(functioncall)
        if len(tokens) == 0:
            return functioncalls
        if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != '+':
            print('Parsing error')
            return None
        tokens = tokens[1:]

def InterpretInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    try:
        return int(token[1])
    except:
        return None

def Hex2Bytes(hexadecimal):
    if len(hexadecimal) % 2 == 1:
        hexadecimal = '0' + hexadecimal
    try:
        return binascii.a2b_hex(hexadecimal)
    except:
        return None

def InterpretHexInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith('0x'):
        return None
    bytes = Hex2Bytes(token[1][2:])
    if bytes == None:
        return None
    integer = 0
    for byte in bytes:
        integer = integer * 0x100 + C2IIP2(byte)
    return integer

def InterpretNumber(token):
    number = InterpretInteger(token)
    if number == None:
        return InterpretHexInteger(token)
    else:
        return number

def InterpretBytes(token):
    if token[0] == STATE_STRING:
        return token[1]
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith('0x'):
        return None
    return Hex2Bytes(token[1][2:])

def CheckFunction(functionname, arguments, countarguments, maxcountarguments=None):
    if maxcountarguments == None:
        if countarguments == 0 and len(arguments) != 0:
            print('Error: function %s takes no arguments, %d are given' % (functionname, len(arguments)))
            return True
        if countarguments == 1 and len(arguments) != 1:
            print('Error: function %s takes 1 argument, %d are given' % (functionname, len(arguments)))
            return True
        if countarguments != len(arguments):
            print('Error: function %s takes %d arguments, %d are given' % (functionname, countarguments, len(arguments)))
            return True
    else:
        if len(arguments) < countarguments or len(arguments) > maxcountarguments:
            print('Error: function %s takes between %d and %d arguments, %d are given' % (functionname, countarguments, maxcountarguments, len(arguments)))
            return True
    return False

def CheckNumber(argument, minimum=None, maximum=None):
    number = InterpretNumber(argument)
    if number == None:
        print('Error: argument should be a number: %s' % argument[1])
        return None
    if minimum != None and number < minimum:
        print('Error: argument should be minimum %d: %d' % (minimum, number))
        return None
    if maximum != None and number > maximum:
        print('Error: argument should be maximum %d: %d' % (maximum, number))
        return None
    return number

def Interpret(expression):
    functioncalls = Parse(expression)
    if functioncalls == None:
        return None
    decoded = ''
    for functioncall in functioncalls:
        functionname, arguments = functioncall
        if functionname == FUNCTIONNAME_REPEAT:
            if CheckFunction(functionname, arguments, 2):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            bytes = InterpretBytes(arguments[1])
            if bytes == None:
                print('Error: argument should be a byte sequence: %s' % arguments[1][1])
                return None
            decoded += number * bytes
        elif functionname == FUNCTIONNAME_RANDOM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            decoded += ''.join([chr(random.randint(0, 255)) for x in range(number)])
        elif functionname == FUNCTIONNAME_LOREMIPSUM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number == None:
                return None
            decoded += LoremIpsum(number)
        elif functionname == FUNCTIONNAME_CHR:
            if CheckFunction(functionname, arguments, 1, 2):
                return None
            number = CheckNumber(arguments[0], minimum=0, maximum=255)
            if number == None:
                return None
            if len(arguments) == 1:
                decoded += chr(number)
            else:
                number2 = CheckNumber(arguments[1], minimum=0, maximum=255)
                if number2 == None:
                    return None
                if number < number2:
                    decoded += ''.join([chr(n) for n in range(number, number2 + 1)])
                else:
                    decoded += ''.join([chr(n) for n in range(number, number2 - 1, -1)])
        else:
            print('Error: unknown function: %s' % functionname)
            return None
    return decoded

FCH_FILENAME = 0
FCH_DATA = 1
FCH_ERROR = 2

def FilenameCheckHash(filename, literalfilename):
    if literalfilename:
        return FCH_FILENAME, filename
    elif filename.startswith('#h#'):
        result = Hex2Bytes(filename[3:])
        if result == None:
            return FCH_ERROR, 'hexadecimal'
        else:
            return FCH_DATA, result
    elif filename.startswith('#b#'):
        try:
            return FCH_DATA, binascii.a2b_base64(filename[3:])
        except:
            return FCH_ERROR, 'base64'
    elif filename.startswith('#e#'):
        result = Interpret(filename[3:])
        if result == None:
            return FCH_ERROR, 'expression'
        else:
            return FCH_DATA, result
    elif filename.startswith('#'):
        return FCH_DATA, C2BIP3(filename[1:])
    else:
        return FCH_FILENAME, filename

def AnalyzeFileError(filename):
    PrintError('Error opening file %s' % filename)
    PrintError(sys.exc_info()[1])
    try:
        if not os.path.exists(filename):
            PrintError('The file does not exist')
        elif os.path.isdir(filename):
            PrintError('The file is a directory')
        elif not os.path.isfile(filename):
            PrintError('The file is not a regular file')
    except:
        pass

class cBinaryFile:
    def __init__(self, filename, zippassword='infected', noextraction=False, literalfilename=False):
        self.filename = filename
        self.zippassword = zippassword
        self.noextraction = noextraction
        self.literalfilename = literalfilename
        self.oZipfile = None
        self.extracted = False
        self.fIn = None

        fch, data = FilenameCheckHash(self.filename, self.literalfilename)
        if fch == FCH_ERROR:
            line = 'Error %s parsing filename: %s' % (data, self.filename)
            raise Exception(line)

        try:
            if self.filename == '':
                if sys.platform == 'win32':
                    import msvcrt
                    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
                self.fIn = sys.stdin
            elif fch == FCH_DATA:
                self.fIn = DataIO(data)
            elif not self.noextraction and self.filename.lower().endswith('.zip'):
                self.oZipfile = CreateZipFileObject(self.filename, 'r')
                if len(self.oZipfile.infolist()) == 1:
                    self.fIn = self.oZipfile.open(self.oZipfile.infolist()[0], 'r', C2BIP3(self.zippassword))
                    self.extracted = True
                else:
                    self.oZipfile.close()
                    self.oZipfile = None
                    self.fIn = open(self.filename, 'rb')
            elif not self.noextraction and self.filename.lower().endswith('.gz'):
                self.fIn = gzip.GzipFile(self.filename, 'rb')
                self.extracted = True
            else:
                self.fIn = open(self.filename, 'rb')
        except:
            AnalyzeFileError(self.filename)
            raise

    def close(self):
        if self.fIn != sys.stdin and self.fIn != None:
            self.fIn.close()
        if self.oZipfile != None:
            self.oZipfile.close()

    def read(self, size=None):
        try:
            fRead = self.fIn.buffer
        except:
            fRead = self.fIn
        if size == None:
            return fRead.read()
        else:
            return fRead.read(size)

    def Data(self):
        data = self.read()
        self.close()
        return data

#-ENDCODE cBinaryFile--------------------------------------------------------------------------------

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

def Magic(data):
    magicPrintable = ''
    magicHex = ''
    for iter in range(4):
        if len(data) >= iter + 1:
            if P23Ord(data[iter]) >= 0x20 and P23Ord(data[iter]) < 0x7F:
                magicPrintable += P23Chr(data[iter])
            else:
                magicPrintable += '.'
            magicHex += '%02x' % P23Ord(data[iter])
    return magicPrintable, magicHex

def CalculateByteStatistics(dPrevalence):
    sumValues = sum(dPrevalence.values())
    countNullByte = dPrevalence[0]
    countControlBytes = 0
    countWhitespaceBytes = 0
    countUniqueBytes = 0
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
            countUniqueBytes += 1
    return sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

def CalculateFileMetaData(data):
    dPrevalence = {}
    for iter in range(256):
        dPrevalence[iter] = 0
    for char in data:
        dPrevalence[P23Ord(char)] += 1

    fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    magicPrintable, magicHex = Magic(data[0:4])
    return hashlib.md5(data).hexdigest(), magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes

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
    if data == None:
        return ''
    return hashlib.md5(data).hexdigest()

def ExtraInfoSHA1(data):
    if data == None:
        return ''
    return hashlib.sha1(data).hexdigest()

def ExtraInfoSHA256(data):
    if data == None:
        return ''
    return hashlib.sha256(data).hexdigest()

def ExtraInfoENTROPY(data):
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
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
    if data == None:
        return ''
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
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[P23Ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def GenerateExtraInfo(extra, index, zipfilename, filename, encrypted, timestamp, stream):
    if extra == '':
        return ''
    if extra.startswith('!') or extra.startswith('#'):
        extra = extra[1:]
    dExtras = {'%INDEX%': lambda x: '%d' % index,
               '%ZIPFILENAME%': lambda x: zipfilename,
               '%FILENAME%': lambda x: filename,
               '%ENCRYPTED%': lambda x: '%d' % encrypted,
               '%TIMESTAMP%': lambda x: timestamp,
               '%LENGTH%': lambda x: IFF(stream == None, '', lambda: '%d' % len(stream)),
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
    return extra.replace(r'\t', '\t').replace(r'\n', '\n')

def Format(string, length):
    spaces = ' ' * (length - len(string))
    if string.isdigit():
        return spaces + string
    else:
        return string + spaces

def PrintOutput(output, outputExtraInfo, extra, separator, quote, fOut):
    if extra.startswith('!'):
        for line in outputExtraInfo[1:]:
            Print(line, fOut)
    elif extra.startswith('#'):
        dOutput = {}
        for line in outputExtraInfo[1:]:
            if line in dOutput:
                dOutput[line] += 1
            else:
                dOutput[line] = 1
        for line, counter in sorted(dOutput.items(), key=operator.itemgetter(1)):
            Print('%4d: %s' % (counter, line), fOut)
    else:
        if separator != '':
            for i in range(len(output)):
                Print(MakeCSVLine(output[i], separator, quote) + separator + outputExtraInfo[i], fOut)
        else:
            stringsOutput = [tuple(map(ToString, row)) for row in output]
            lengthMaxRow = max([len(row) for row in output])
            lengthsMax = [0 for i in range(lengthMaxRow)]
            for i in range(lengthMaxRow):
                for row in stringsOutput:
                    if i < len(row):
                        lengthsMax[i] = max(lengthsMax[i], len(row[i]))
            for i in range(len(stringsOutput)):
                Print(' '.join([Format(stringsOutput[i][j], lengthsMax[j]) for j in range(len(stringsOutput[i]))]) + ' ' + outputExtraInfo[i], fOut)

def IsNumeric(value):
    if value == '':
        return False
    for c in value:
        if c < '0' or c > '9':
            return False
    return True

def DecideToSelect(selectvalue, counter, zipfilename):
    if selectvalue == '':
        return True
    if IsNumeric(selectvalue) and selectvalue == str(counter):
        return True
    return selectvalue == zipfilename

def GetDictionary(passwordfile):
    if passwordfile != '.':
        return File2Strings(passwordfile)
    else:
# https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/password.lst
        return [
          'infected',
          'P@ssw0rd',
          '123456',
          '12345',
          'password',
          'password1',
          '123456789',
          '12345678',
          '1234567890',
          'abc123',
          'computer',
          'tigger',
          '1234',
          'qwerty',
          'money',
          'carmen',
          'mickey',
          'secret',
          'summer',
          'internet',
          'a1b2c3',
          '123',
          'service',
          'canada',
          'hello',
          'ranger',
          'shadow',
          'baseball',
          'donald',
          'harley',
          'hockey',
          'letmein',
          'maggie',
          'mike',
          'mustang',
          'snoopy',
          'buster',
          'dragon',
          'jordan',
          'michael',
          'michelle',
          'mindy',
          'patrick',
          '123abc',
          'andrew',
          'bear',
          'calvin',
          'changeme',
          'diamond',
          'fuckme',
          'fuckyou',
          'matthew',
          'miller',
          'tiger',
          'trustno1',
          'alex',
          'apple',
          'avalon',
          'brandy',
          'chelsea',
          'coffee',
          'falcon',
          'freedom',
          'gandalf',
          'green',
          'helpme',
          'linda',
          'magic',
          'merlin',
          'newyork',
          'soccer',
          'thomas',
          'wizard',
          'asdfgh',
          'bandit',
          'batman',
          'boris',
          'butthead',
          'dorothy',
          'eeyore',
          'fishing',
          'football',
          'george',
          'happy',
          'iloveyou',
          'jennifer',
          'jonathan',
          'love',
          'marina',
          'master',
          'missy',
          'monday',
          'monkey',
          'natasha',
          'ncc1701',
          'pamela',
          'pepper',
          'piglet',
          'poohbear',
          'pookie',
          'rabbit',
          'rachel',
          'rocket',
          'rose',
          'smile',
          'sparky',
          'spring',
          'steven',
          'success',
          'sunshine',
          'victoria',
          'whatever',
          'zapata',
          '8675309',
          'amanda',
          'andy',
          'angel',
          'august',
          'barney',
          'biteme',
          'boomer',
          'brian',
          'casey',
          'cowboy',
          'delta',
          'doctor',
          'fisher',
          'island',
          'john',
          'joshua',
          'karen',
          'marley',
          'orange',
          'please',
          'rascal',
          'richard',
          'sarah',
          'scooter',
          'shalom',
          'silver',
          'skippy',
          'stanley',
          'taylor',
          'welcome',
          'zephyr',
          '111111',
          'aaaaaa',
          'access',
          'albert',
          'alexander',
          'andrea',
          'anna',
          'anthony',
          'asdfjkl;',
          'ashley',
          'basketball',
          'beavis',
          'black',
          'bob',
          'booboo',
          'bradley',
          'brandon',
          'buddy',
          'caitlin',
          'camaro',
          'charlie',
          'chicken',
          'chris',
          'cindy',
          'cricket',
          'dakota',
          'dallas',
          'daniel',
          'david',
          'debbie',
          'dolphin',
          'elephant',
          'emily',
          'friend',
          'fucker',
          'ginger',
          'goodluck',
          'hammer',
          'heather',
          'iceman',
          'jason',
          'jessica',
          'jesus',
          'joseph',
          'jupiter',
          'justin',
          'kevin',
          'knight',
          'lacrosse',
          'lakers',
          'lizard',
          'madison',
          'mary',
          'mother',
          'muffin',
          'murphy',
          'nirvana',
          'paris',
          'pentium',
          'phoenix',
          'picture',
          'rainbow',
          'sandy',
          'saturn',
          'scott',
          'shannon',
          'shithead',
          'skeeter',
          'sophie',
          'special',
          'stephanie',
          'stephen',
          'steve',
          'sweetie',
          'teacher',
          'tennis',
          'test',
          'test123',
          'tommy',
          'topgun',
          'tristan',
          'wally',
          'william',
          'wilson',
          '1q2w3e',
          '654321',
          '666666',
          'a12345',
          'a1b2c3d4',
          'alpha',
          'amber',
          'angela',
          'angie',
          'archie',
          'asdf',
          'blazer',
          'bond007',
          'booger',
          'charles',
          'christin',
          'claire',
          'control',
          'danny',
          'david1',
          'dennis',
          'digital',
          'disney',
          'edward',
          'elvis',
          'felix',
          'flipper',
          'franklin',
          'frodo',
          'honda',
          'horses',
          'hunter',
          'indigo',
          'james',
          'jasper',
          'jeremy',
          'julian',
          'kelsey',
          'killer',
          'lauren',
          'marie',
          'maryjane',
          'matrix',
          'maverick',
          'mayday',
          'mercury',
          'mitchell',
          'morgan',
          'mountain',
          'niners',
          'nothing',
          'oliver',
          'peace',
          'peanut',
          'pearljam',
          'phantom',
          'popcorn',
          'princess',
          'psycho',
          'pumpkin',
          'purple',
          'randy',
          'rebecca',
          'reddog',
          'robert',
          'rocky',
          'roses',
          'salmon',
          'samson',
          'sharon',
          'sierra',
          'smokey',
          'startrek',
          'steelers',
          'stimpy',
          'sunflower',
          'superman',
          'support',
          'sydney',
          'techno',
          'walter',
          'willie',
          'willow',
          'winner',
          'ziggy',
          'zxcvbnm',
          'alaska',
          'alexis',
          'alice',
          'animal',
          'apples',
          'barbara',
          'benjamin',
          'billy',
          'blue',
          'bluebird',
          'bobby',
          'bonnie',
          'bubba',
          'camera',
          'chocolate',
          'clark',
          'claudia',
          'cocacola',
          'compton',
          'connect',
          'cookie',
          'cruise',
          'douglas',
          'dreamer',
          'dreams',
          'duckie',
          'eagles',
          'eddie',
          'einstein',
          'enter',
          'explorer',
          'faith',
          'family',
          'ferrari',
          'flamingo',
          'flower',
          'foxtrot',
          'francis',
          'freddy',
          'friday',
          'froggy',
          'giants',
          'gizmo',
          'global',
          'goofy',
          'happy1',
          'hendrix',
          'henry',
          'herman',
          'homer',
          'honey',
          'house',
          'houston',
          'iguana',
          'indiana',
          'insane',
          'inside',
          'irish',
          'ironman',
          'jake',
          'jasmin',
          'jeanne',
          'jerry',
          'joey',
          'justice',
          'katherine',
          'kermit',
          'kitty',
          'koala',
          'larry',
          'leslie',
          'logan',
          'lucky',
          'mark',
          'martin',
          'matt',
          'minnie',
          'misty',
          'mitch',
          'mouse',
          'nancy',
          'nascar',
          'nelson',
          'pantera',
          'parker',
          'penguin',
          'peter',
          'piano',
          'pizza',
          'prince',
          'punkin',
          'pyramid',
          'raymond',
          'robin',
          'roger',
          'rosebud',
          'route66',
          'royal',
          'running',
          'sadie',
          'sasha',
          'security',
          'sheena',
          'sheila',
          'skiing',
          'snapple',
          'snowball',
          'sparrow',
          'spencer',
          'spike',
          'star',
          'stealth',
          'student',
          'sunny',
          'sylvia',
          'tamara',
          'taurus',
          'teresa',
          'theresa',
          'thunderbird',
          'tigers',
          'tony',
          'toyota',
          'travel',
          'tuesday',
          'victory',
          'viper1',
          'wesley',
          'whisky',
          'winnie',
          'winter',
          'wolves',
          'xyz123',
          'zorro',
          '123123',
          '1234567',
          '696969',
          '888888',
          'Anthony',
          'Joshua',
          'Matthew',
          'Tigger',
          'aaron',
          'abby',
          'abcdef',
          'adidas',
          'adrian',
          'alfred',
          'arthur',
          'athena',
          'austin',
          'awesome',
          'badger',
          'bamboo',
          'beagle',
          'bears',
          'beatles',
          'beautiful',
          'beaver',
          'benny',
          'bigmac',
          'bingo',
          'bitch',
          'blonde',
          'boogie',
          'boston',
          'brenda',
          'bright',
          'bubba1',
          'bubbles',
          'buffy',
          'button',
          'buttons',
          'cactus',
          'candy',
          'captain',
          'carlos',
          'caroline',
          'carrie',
          'casper',
          'catch22',
          'chance',
          'charity',
          'charlotte',
          'cheese',
          'cheryl',
          'chloe',
          'chris1',
          'clancy',
          'compaq',
          'conrad',
          'cooper',
          'cooter',
          'copper',
          'cosmos',
          'cougar',
          'cracker',
          'crawford',
          'crystal',
          'curtis',
          'cyclone',
          'dance',
          'diablo',
          'dollars',
          'dookie',
          'dumbass',
          'dundee',
          'elizabeth',
          'eric',
          'europe',
          'farmer',
          'firebird',
          'fletcher',
          'fluffy',
          'france',
          'freak1',
          'friends',
          'fuckoff',
          'gabriel',
          'galaxy',
          'gambit',
          'garden',
          'garfield',
          'garnet',
          'genesis',
          'genius',
          'godzilla',
          'golfer',
          'goober',
          'grace',
          'greenday',
          'groovy',
          'grover',
          'guitar',
          'hacker',
          'harry',
          'hazel',
          'hector',
          'herbert',
          'horizon',
          'hornet',
          'howard',
          'icecream',
          'imagine',
          'impala',
          'jack',
          'janice',
          'jasmine',
          'jason1',
          'jeanette',
          'jeffrey',
          'jenifer',
          'jenni',
          'jesus1',
          'jewels',
          'joker',
          'julie',
          'julie1',
          'junior',
          'justin1',
          'kathleen',
          'keith',
          'kelly',
          'kelly1',
          'kennedy',
          'kevin1',
          'knicks',
          'larry1',
          'leonard',
          'lestat',
          'library',
          'lincoln',
          'lionking',
          'london',
          'louise',
          'lucky1',
          'lucy',
          'maddog',
          'margaret',
          'mariposa',
          'marlboro',
          'martin1',
          'marty',
          'master1',
          'mensuck',
          'mercedes',
          'metal',
          'midori',
          'mikey',
          'millie',
          'mirage',
          'molly',
          'monet',
          'money1',
          'monica',
          'monopoly',
          'mookie',
          'moose',
          'moroni',
          'music',
          'naomi',
          'nathan',
          'nguyen',
          'nicholas',
          'nicole',
          'nimrod',
          'october',
          'olive',
          'olivia',
          'online',
          'oscar',
          'oxford',
          'pacific',
          'painter',
          'peaches',
          'penelope',
          'pepsi',
          'petunia',
          'philip',
          'phoenix1',
          'photo',
          'pickle',
          'player',
          'poiuyt',
          'porsche',
          'porter',
          'puppy',
          'python',
          'quality',
          'raquel',
          'raven',
          'remember',
          'robbie',
          'robert1',
          'roman',
          'rugby',
          'runner',
          'russell',
          'ryan',
          'sailing',
          'sailor',
          'samantha',
          'savage',
          'scarlett',
          'school',
          'sean',
          'seven',
          'shadow1',
          'sheba',
          'shelby',
          'shit',
          'shoes',
          'simba',
          'simple',
          'skipper',
          'smiley',
          'snake',
          'snickers',
          'sniper',
          'snoopdog',
          'snowman',
          'sonic',
          'spitfire',
          'sprite',
          'spunky',
          'starwars',
          'station',
          'stella',
          'stingray',
          'storm',
          'stormy',
          'stupid',
          'sunny1',
          'sunrise',
          'surfer',
          'susan',
          'tammy',
          'tango',
          'tanya',
          'teddy1',
          'theboss',
          'theking',
          'thumper',
          'tina',
          'tintin',
          'tomcat',
          'trebor',
          'trevor',
          'tweety',
          'unicorn',
          'valentine',
          'valerie',
          'vanilla',
          'veronica',
          'victor',
          'vincent',
          'viper',
          'warrior',
          'warriors',
          'weasel',
          'wheels',
          'wilbur',
          'winston',
          'wisdom',
          'wombat',
          'xavier',
          'yellow',
          'zeppelin',
          '1111',
          '1212',
          'Andrew',
          'Family',
          'Friends',
          'Michael',
          'Michelle',
          'Snoopy',
          'abcd1234',
          'abcdefg',
          'abigail',
          'account',
          'adam',
          'alex1',
          'alice1',
          'allison',
          'alpine',
          'andre1',
          'andrea1',
          'angel1',
          'anita',
          'annette',
          'antares',
          'apache',
          'apollo',
          'aragorn',
          'arizona',
          'arnold',
          'arsenal',
          'asdfasdf',
          'asdfg',
          'asdfghjk',
          'avenger',
          'baby',
          'babydoll',
          'bailey',
          'banana',
          'barry',
          'basket',
          'batman1',
          'beaner',
          'beast',
          'beatrice',
          'bella',
          'bertha',
          'bigben',
          'bigdog',
          'biggles',
          'bigman',
          'binky',
          'biology',
          'bishop',
          'blondie',
          'bluefish',
          'bobcat',
          'bosco',
          'braves',
          'brazil',
          'bruce',
          'bruno',
          'brutus',
          'buffalo',
          'bulldog',
          'bullet',
          'bullshit',
          'bunny',
          'business',
          'butch',
          'butler',
          'butter',
          'california',
          'carebear',
          'carol',
          'carol1',
          'carole',
          'cassie',
          'castle',
          'catalina',
          'catherine',
          'cccccc',
          'celine',
          'center',
          'champion',
          'chanel',
          'chaos',
          'chelsea1',
          'chester1',
          'chicago',
          'chico',
          'christian',
          'christy',
          'church',
          'cinder',
          'colleen',
          'colorado',
          'columbia',
          'commander',
          'connie',
          'cookies',
          'cooking',
          'corona',
          'cowboys',
          'coyote',
          'craig',
          'creative',
          'cuddles',
          'cuervo',
          'cutie',
          'daddy',
          'daisy',
          'daniel1',
          'danielle',
          'davids',
          'death',
          'denis',
          'derek',
          'design',
          'destiny',
          'diana',
          'diane',
          'dickhead',
          'digger',
          'dodger',
          'donna',
          'dougie',
          'dragonfly',
          'dylan',
          'eagle',
          'eclipse',
          'electric',
          'emerald',
          'etoile',
          'excalibur',
          'express',
          'fender',
          'fiona',
          'fireman',
          'flash',
          'florida',
          'flowers',
          'foster',
          'francesco',
          'francine',
          'francois',
          'frank',
          'french',
          'fuckface',
          'gemini',
          'general',
          'gerald',
          'germany',
          'gilbert',
          'goaway',
          'golden',
          'goldfish',
          'goose',
          'gordon',
          'graham',
          'grant',
          'gregory',
          'gretchen',
          'gunner',
          'hannah',
          'harold',
          'harrison',
          'harvey',
          'hawkeye',
          'heaven',
          'heidi',
          'helen',
          'helena',
          'hithere',
          'hobbit',
          'ibanez',
          'idontknow',
          'integra',
          'ireland',
          'irene',
          'isaac',
          'isabel',
          'jackass',
          'jackie',
          'jackson',
          'jaguar',
          'jamaica',
          'japan',
          'jenny1',
          'jessie',
          'johan',
          'johnny',
          'joker1',
          'jordan23',
          'judith',
          'julia',
          'jumanji',
          'kangaroo',
          'karen1',
          'kathy',
          'keepout',
          'keith1',
          'kenneth',
          'kimberly',
          'kingdom',
          'kitkat',
          'kramer',
          'kristen',
          'laura',
          'laurie',
          'lawrence',
          'lawyer',
          'legend',
          'liberty',
          'light',
          'lindsay',
          'lindsey',
          'lisa',
          'liverpool',
          'lola',
          'lonely',
          'louis',
          'lovely',
          'loveme',
          'lucas',
          'madonna',
          'malcolm',
          'malibu',
          'marathon',
          'marcel',
          'maria1',
          'mariah',
          'mariah1',
          'marilyn',
          'mario',
          'marvin',
          'maurice',
          'maxine',
          'maxwell',
          'me',
          'meggie',
          'melanie',
          'melissa',
          'melody',
          'mexico',
          'michael1',
          'michele',
          'midnight',
          'mike1',
          'miracle',
          'misha',
          'mishka',
          'molly1',
          'monique',
          'montreal',
          'moocow',
          'moore',
          'morris',
          'mouse1',
          'mulder',
          'nautica',
          'nellie',
          'newton',
          'nick',
          'nirvana1',
          'nissan',
          'norman',
          'notebook',
          'ocean',
          'olivier',
          'ollie',
          'oranges',
          'oregon',
          'orion',
          'panda',
          'pandora',
          'panther',
          'passion',
          'patricia',
          'pearl',
          'peewee',
          'pencil',
          'penny',
          'people',
          'percy',
          'person',
          'peter1',
          'petey',
          'picasso',
          'pierre',
          'pinkfloyd',
          'polaris',
          'police',
          'pookie1',
          'poppy',
          'power',
          'predator',
          'preston',
          'q1w2e3',
          'queen',
          'queenie',
          'quentin',
          'ralph',
          'random',
          'rangers',
          'raptor',
          'reality',
          'redrum',
          'remote',
          'reynolds',
          'rhonda',
          'ricardo',
          'ricardo1',
          'ricky',
          'river',
          'roadrunner',
          'robinhood',
          'rocknroll',
          'rocky1',
          'ronald',
          'roxy',
          'ruthie',
          'sabrina',
          'sakura',
          'sally',
          'sampson',
          'samuel',
          'sandra',
          'santa',
          'sapphire',
          'scarlet',
          'scorpio',
          'scott1',
          'scottie',
          'scruffy',
          'seattle',
          'serena',
          'shanti',
          'shark',
          'shogun',
          'simon',
          'singer',
          'skull',
          'skywalker',
          'slacker',
          'smashing',
          'smiles',
          'snowflake',
          'snuffy',
          'soccer1',
          'soleil',
          'sonny',
          'spanky',
          'speedy',
          'spider',
          'spooky',
          'stacey',
          'star69',
          'start',
          'steven1',
          'stinky',
          'strawberry',
          'stuart',
          'sugar',
          'sundance',
          'superfly',
          'suzanne',
          'suzuki',
          'swimmer',
          'swimming',
          'system',
          'taffy',
          'tarzan',
          'teddy',
          'teddybear',
          'terry',
          'theatre',
          'thunder',
          'thursday',
          'tinker',
          'tootsie',
          'tornado',
          'tracy',
          'tricia',
          'trident',
          'trojan',
          'truman',
          'trumpet',
          'tucker',
          'turtle',
          'tyler',
          'utopia',
          'voyager',
          'warcraft',
          'warlock',
          'warren',
          'water',
          'wayne',
          'wendy',
          'williams',
          'willy',
          'winona',
          'woody',
          'woofwoof',
          'wrangler',
          'wright',
          'xfiles',
          'xxxxxx',
          'yankees',
          'yvonne',
          'zebra',
          'zenith',
          'zigzag',
          'zombie',
          'zxc123',
          'zxcvb',
          '000000',
          '007007',
          '11111',
          '11111111',
          '123321',
          '171717',
          '181818',
          '1a2b3c',
          '1chris',
          '4runner',
          '54321',
          '55555',
          '6969',
          '7777777',
          '789456',
          '88888888',
          'Alexis',
          'Bailey',
          'Charlie',
          'Chris',
          'Daniel',
          'Dragon',
          'Elizabeth',
          'HARLEY',
          'Heather',
          'Jennifer',
          'Jessica',
          'Jordan',
          'KILLER',
          'Nicholas',
          'Password',
          'Princess',
          'Purple',
          'Rebecca',
          'Robert',
          'Shadow',
          'Steven',
          'Summer',
          'Sunshine',
          'Superman',
          'Taylor',
          'Thomas',
          'Victoria',
          'abcd123',
          'abcde',
          'accord',
          'active',
          'africa',
          'airborne',
          'alfaro',
          'alicia',
          'aliens',
          'alina',
          'aline',
          'alison',
          'allen',
          'aloha',
          'alpha1',
          'althea',
          'altima',
          'amanda1',
          'amazing',
          'america',
          'amour',
          'anderson',
          'andre',
          'andrew1',
          'andromeda',
          'angels',
          'angie1',
          'annie',
          'anything',
          'apple1',
          'apple2',
          'applepie',
          'april',
          'aquarius',
          'ariane',
          'ariel',
          'arlene',
          'artemis',
          'asdf1234',
          'asdfjkl',
          'ashley1',
          'ashraf',
          'ashton',
          'asterix',
          'attila',
          'autumn',
          'avatar',
          'babes',
          'bambi',
          'barbie',
          'barney1',
          'barrett',
          'bball',
          'beaches',
          'beanie',
          'beans',
          'beauty',
          'becca',
          'belize',
          'belle',
          'belmont',
          'benji',
          'benson',
          'bernardo',
          'berry',
          'betsy',
          'betty',
          'bigboss',
          'bigred',
          'billy1',
          'birdie',
          'birthday',
          'biscuit',
          'bitter',
          'blackjack',
          'blah',
          'blanche',
          'blood',
          'blowjob',
          'blowme',
          'blueeyes',
          'blues',
          'bogart',
          'bombay',
          'boobie',
          'boots',
          'bootsie',
          'boxers',
          'brandi',
          'brent',
          'brewster',
          'bridge',
          'bronco',
          'bronte',
          'brooke',
          'brother',
          'bryan',
          'bubble',
          'buddha',
          'budgie',
          'burton',
          'butterfly',
          'byron',
          'calendar',
          'calvin1',
          'camel',
          'camille',
          'campbell',
          'camping',
          'cancer',
          'canela',
          'cannon',
          'carbon',
          'carnage',
          'carolyn',
          'carrot',
          'cascade',
          'catfish',
          'cathy',
          'catwoman',
          'cecile',
          'celica',
          'change',
          'chantal',
          'charger',
          'cherry',
          'chiara',
          'chiefs',
          'china',
          'chris123',
          'christ1',
          'christmas',
          'christopher',
          'chuck',
          'cindy1',
          'cinema',
          'civic',
          'claude',
          'clueless',
          'cobain',
          'cobra',
          'cody',
          'colette',
          'college',
          'colors',
          'colt45',
          'confused',
          'cool',
          'corvette',
          'cosmo',
          'country',
          'crusader',
          'cunningham',
          'cupcake',
          'cynthia',
          'dagger',
          'dammit',
          'dancer',
          'daphne',
          'darkstar',
          'darren',
          'darryl',
          'darwin',
          'deborah',
          'december',
          'deedee',
          'deeznuts',
          'delano',
          'delete',
          'demon',
          'denise',
          'denny',
          'desert',
          'deskjet',
          'detroit',
          'devil',
          'devine',
          'devon',
          'dexter',
          'dianne',
          'diesel',
          'director',
          'dixie',
          'dodgers',
          'doggy',
          'dollar',
          'dolly',
          'dominique',
          'domino',
          'dontknow',
          'doogie',
          'doudou',
          'downtown',
          'dragon1',
          'driver',
          'dude',
          'dudley',
          'dutchess',
          'dwight',
          'eagle1',
          'easter',
          'eastern',
          'edith',
          'edmund',
          'eight',
          'element',
          'elissa',
          'ellen',
          'elliot',
          'empire',
          'enigma',
          'enterprise',
          'erin',
          'escort',
          'estelle',
          'eugene',
          'evelyn',
          'explore',
          'family1',
          'fatboy',
          'felipe',
          'ferguson',
          'ferret',
          'ferris',
          'fireball',
          'fishes',
          'fishie',
          'flight',
          'florida1',
          'flowerpot',
          'forward',
          'freddie',
          'freebird',
          'freeman',
          'frisco',
          'fritz',
          'froggie',
          'froggies',
          'frogs',
          'fucku',
          'future',
          'gabby',
          'games',
          'garcia',
          'gaston',
          'gateway',
          'george1',
          'georgia',
          'german',
          'germany1',
          'getout',
          'ghost',
          'gibson',
          'giselle',
          'gmoney',
          'goblin',
          'goblue',
          'gollum',
          'grandma',
          'gremlin',
          'grizzly',
          'grumpy',
          'guess',
          'guitar1',
          'gustavo',
          'haggis',
          'haha',
          'hailey',
          'halloween',
          'hamilton',
          'hamlet',
          'hanna',
          'hanson',
          'happy123',
          'happyday',
          'hardcore',
          'harley1',
          'harriet',
          'harris',
          'harvard',
          'health',
          'heart',
          'heather1',
          'heather2',
          'hedgehog',
          'helene',
          'hello1',
          'hello123',
          'hellohello',
          'hermes',
          'heythere',
          'highland',
          'hilda',
          'hillary',
          'history',
          'hitler',
          'hobbes',
          'holiday',
          'holly',
          'honda1',
          'hongkong',
          'hootie',
          'horse',
          'hotrod',
          'hudson',
          'hummer',
          'huskies',
          'idiot',
          'iforget',
          'iloveu',
          'impact',
          'indonesia',
          'irina',
          'isabelle',
          'israel',
          'italia',
          'italy',
          'jackie1',
          'jacob',
          'jakey',
          'james1',
          'jamesbond',
          'jamie',
          'jamjam',
          'jeffrey1',
          'jennie',
          'jenny',
          'jensen',
          'jesse',
          'jesse1',
          'jester',
          'jethro',
          'jimbob',
          'jimmy',
          'joanna',
          'joelle',
          'john316',
          'jordie',
          'jorge',
          'josh',
          'journey',
          'joyce',
          'jubilee',
          'jules',
          'julien',
          'juliet',
          'junebug',
          'juniper',
          'justdoit',
          'karin',
          'karine',
          'karma',
          'katerina',
          'katie',
          'katie1',
          'kayla',
          'keeper',
          'keller',
          'kendall',
          'kenny',
          'ketchup',
          'kings',
          'kissme',
          'kitten',
          'kittycat',
          'kkkkkk',
          'kristi',
          'kristine',
          'labtec',
          'laddie',
          'ladybug',
          'lance',
          'laurel',
          'lawson',
          'leader',
          'leland',
          'lemon',
          'lester',
          'letter',
          'letters',
          'lexus1',
          'libra',
          'lights',
          'lionel',
          'little',
          'lizzy',
          'lolita',
          'lonestar',
          'longhorn',
          'looney',
          'loren',
          'lorna',
          'loser',
          'lovers',
          'loveyou',
          'lucia',
          'lucifer',
          'lucky14',
          'maddie',
          'madmax',
          'magic1',
          'magnum',
          'maiden',
          'maine',
          'management',
          'manson',
          'manuel',
          'marcus',
          'maria',
          'marielle',
          'marine',
          'marino',
          'marshall',
          'martha',
          'maxmax',
          'meatloaf',
          'medical',
          'megan',
          'melina',
          'memphis',
          'mermaid',
          'miami',
          'michel',
          'michigan',
          'mickey1',
          'microsoft',
          'mikael',
          'milano',
          'miles',
          'millenium',
          'million',
          'miranda',
          'miriam',
          'mission',
          'mmmmmm',
          'mobile',
          'monkey1',
          'monroe',
          'montana',
          'monty',
          'moomoo',
          'moonbeam',
          'morpheus',
          'motorola',
          'movies',
          'mozart',
          'munchkin',
          'murray',
          'mustang1',
          'nadia',
          'nadine',
          'napoleon',
          'nation',
          'national',
          'nestle',
          'newlife',
          'newyork1',
          'nichole',
          'nikita',
          'nikki',
          'nintendo',
          'nokia',
          'nomore',
          'normal',
          'norton',
          'noway',
          'nugget',
          'number9',
          'numbers',
          'nurse',
          'nutmeg',
          'ohshit',
          'oicu812',
          'omega',
          'openup',
          'orchid',
          'oreo',
          'orlando',
          'packard',
          'packers',
          'paloma',
          'pancake',
          'panic',
          'parola',
          'parrot',
          'partner',
          'pascal',
          'patches',
          'patriots',
          'paula',
          'pauline',
          'payton',
          'peach',
          'peanuts',
          'pedro1',
          'peggy',
          'perfect',
          'perry',
          'peterpan',
          'philips',
          'phillips',
          'phone',
          'pierce',
          'pigeon',
          'pink',
          'pioneer',
          'piper1',
          'pirate',
          'pisces',
          'playboy',
          'pluto',
          'poetry',
          'pontiac',
          'pookey',
          'popeye',
          'prayer',
          'precious',
          'prelude',
          'premier',
          'puddin',
          'pulsar',
          'pussy',
          'pussy1',
          'qwert',
          'qwerty12',
          'qwertyui',
          'rabbit1',
          'rachelle',
          'racoon',
          'rambo',
          'randy1',
          'ravens',
          'redman',
          'redskins',
          'reggae',
          'reggie',
          'renee',
          'renegade',
          'rescue',
          'revolution',
          'richard1',
          'richards',
          'richmond',
          'riley',
          'ripper',
          'robby',
          'roberts',
          'rock',
          'rocket1',
          'rockie',
          'rockon',
          'roger1',
          'rogers',
          'roland',
          'rommel',
          'rookie',
          'rootbeer',
          'rosie',
          'rufus',
          'rusty',
          'ruthless',
          'sabbath',
          'sabina',
          'safety',
          'saint',
          'samiam',
          'sammie',
          'sammy',
          'samsam',
          'sandi',
          'sanjose',
          'saphire',
          'sarah1',
          'saskia',
          'sassy',
          'saturday',
          'science',
          'scooby',
          'scoobydoo',
          'scooter1',
          'scorpion',
          'scotty',
          'scouts',
          'search',
          'september',
          'server',
          'seven7',
          'sexy',
          'shaggy',
          'shanny',
          'shaolin',
          'shasta',
          'shayne',
          'shelly',
          'sherry',
          'shirley',
          'shorty',
          'shotgun',
          'sidney',
          'simba1',
          'sinatra',
          'sirius',
          'skate',
          'skipper1',
          'skyler',
          'slayer',
          'sleepy',
          'slider',
          'smile1',
          'smitty',
          'smoke',
          'snakes',
          'snapper',
          'snoop',
          'solomon',
          'sophia',
          'space',
          'sparks',
          'spartan',
          'spike1',
          'sponge',
          'spurs',
          'squash',
          'stargate',
          'starlight',
          'stars',
          'steph1',
          'steve1',
          'stevens',
          'stewart',
          'stone',
          'stranger',
          'stretch',
          'strong',
          'studio',
          'stumpy',
          'sucker',
          'suckme',
          'sultan',
          'summit',
          'sunfire',
          'sunset',
          'super',
          'superstar',
          'surfing',
          'susan1',
          'sutton',
          'sweden',
          'sweetpea',
          'sweety',
          'swordfish',
          'tabatha',
          'tacobell',
          'taiwan',
          'tamtam',
          'tanner',
          'target',
          'tasha',
          'tattoo',
          'tequila',
          'terry1',
          'texas',
          'thankyou',
          'theend',
          'thompson',
          'thrasher',
          'tiger2',
          'timber',
          'timothy',
          'tinkerbell',
          'topcat',
          'topher',
          'toshiba',
          'tototo',
          'travis',
          'treasure',
          'trees',
          'tricky',
          'trish',
          'triton',
          'trombone',
          'trouble',
          'trucker',
          'turbo',
          'twins',
          'tyler1',
          'ultimate',
          'unique',
          'united',
          'ursula',
          'vacation',
          'valley',
          'vampire',
          'vanessa',
          'venice',
          'venus',
          'vermont',
          'vicki',
          'vicky',
          'victor1',
          'vincent1',
          'violet',
          'violin',
          'virgil',
          'virginia',
          'vision',
          'volley',
          'voodoo',
          'vortex',
          'waiting',
          'wanker',
          'warner',
          'water1',
          'wayne1',
          'webster',
          'weezer',
          'wendy1',
          'western',
          'white',
          'whitney',
          'whocares',
          'wildcat',
          'william1',
          'wilma',
          'window',
          'winniethepooh',
          'wolfgang',
          'wolverine',
          'wonder',
          'xxxxxxxx',
          'yamaha',
          'yankee',
          'yogibear',
          'yolanda',
          'yomama',
          'yvette',
          'zachary',
          'zebras',
          'zxcvbn',
          '00000000',
          '121212',
          '1234qwer',
          '131313',
          '13579',
          '90210',
          '99999999',
          'ABC123',
          'action',
          'amelie',
          'anaconda',
          'apollo13',
          'artist',
          'asshole',
          'benoit',
          'bernard',
          'bernie',
          'bigbird',
          'blizzard',
          'bluesky',
          'bonjour',
          'caesar',
          'cardinal',
          'carolina',
          'cesar',
          'chandler',
          'chapman',
          'charlie1',
          'chevy',
          'chiquita',
          'chocolat',
          'coco',
          'cougars',
          'courtney',
          'dolphins',
          'dominic',
          'donkey',
          'dusty',
          'eminem',
          'energy',
          'fearless',
          'forest',
          'forever',
          'glenn',
          'guinness',
          'hotdog',
          'indian',
          'jared',
          'jimbo',
          'johnson',
          'jojo',
          'josie',
          'kristin',
          'lloyd',
          'lorraine',
          'lynn',
          'maxime',
          'memory',
          'mimi',
          'mirror',
          'nebraska',
          'nemesis',
          'network',
          'nigel',
          'oatmeal',
          'patton',
          'pedro',
          'planet',
          'players',
          'portland',
          'praise',
          'psalms',
          'qwaszx',
          'raiders',
          'rambo1',
          'rancid',
          'shawn',
          'shelley',
          'softball',
          'speedo',
          'sports',
          'ssssss',
          'steele',
          'steph',
          'stephani',
          'sunday',
          'tiffany',
          'tigre',
          'toronto',
          'trixie',
          'undead',
          'valentin',
          'velvet',
          'viking',
          'walker',
          'watson',
          'young',
          'babygirl',
          'pretty',
          'hottie',
          'teamo',
          '987654321',
          'naruto',
          'spongebob',
          'daniela',
          'princesa',
          'christ',
          'blessed',
          'single',
          'qazwsx',
          'pokemon',
          'iloveyou1',
          'iloveyou2',
          'fuckyou1',
          'hahaha',
          'poop',
          'blessing',
          'blahblah',
          'blink182',
          '123qwe',
          'trinity',
          'passw0rd',
          'google',
          'looking',
          'spirit',
          'iloveyou!',
          'qwerty1',
          'onelove',
          'mylove',
          '222222',
          'ilovegod',
          'football1',
          'loving',
          'emmanuel',
          '1q2w3e4r',
          'red123',
          'blabla',
          '112233',
          'hallo',
          'spiderman',
          'simpsons',
          'monster',
          'november',
          'brooklyn',
          'poopoo',
          'darkness',
          '159753',
          'pineapple',
          'chester',
          '1qaz2wsx',
          'drowssap',
          'monkey12',
          'wordpass',
          'q1w2e3r4',
          'coolness',
          '11235813',
          'something',
          'alexandra',
          'estrella',
          'miguel',
          'iloveme',
          'sayang',
          'princess1',
          '555555',
          '999999',
          'alejandro',
          'brittany',
          'alejandra',
          'tequiero',
          'antonio',
          '987654',
          '00000',
          'fernando',
          'corazon',
          'cristina',
          'kisses',
          'myspace',
          'rebelde',
          'babygurl',
          'alyssa',
          'mahalkita',
          'gabriela',
          'pictures',
          'hellokitty',
          'babygirl1',
          'angelica',
          'mahalko',
          'mariana',
          'eduardo',
          'andres',
          'ronaldo',
          'inuyasha',
          'adriana',
          'celtic',
          'samsung',
          'angelo',
          '456789',
          'sebastian',
          'karina',
          'hotmail',
          '0123456789',
          'barcelona',
          'cameron',
          'slipknot',
          'cutiepie',
          '50cent',
          'bonita',
          'maganda',
          'babyboy',
          'natalie',
          'cuteako',
          'javier',
          '789456123',
          '123654',
          'bowwow',
          'portugal',
          '777777',
          'volleyball',
          'january',
          'cristian',
          'bianca',
          'chrisbrown',
          '101010',
          'sweet',
          'panget',
          'benfica',
          'love123',
          'lollipop',
          'camila',
          'qwertyuiop',
          'harrypotter',
          'ihateyou',
          'christine',
          'lorena',
          'andreea',
          'charmed',
          'rafael',
          'brianna',
          'aaliyah',
          'johncena',
          'lovelove',
          'gangsta',
          '333333',
          'hiphop',
          'mybaby',
          'sergio',
          'metallica',
          'myspace1',
          'babyblue',
          'badboy',
          'fernanda',
          'westlife',
          'sasuke',
          'steaua',
          'roberto',
          'slideshow',
          'asdfghjkl',
          'santiago',
          'jayson',
          '5201314',
          'jerome',
          'gandako',
          'gatita',
          'babyko',
          '246810',
          'sweetheart',
          'chivas',
          'alberto',
          'valeria',
          'nicole1',
          '12345678910',
          'leonardo',
          'jayjay',
          'liliana',
          'sexygirl',
          '232323',
          'amores',
          'anthony1',
          'bitch1',
          'fatima',
          'miamor',
          'lover',
          'lalala',
          '252525',
          'skittles',
          'colombia',
          '159357',
          'manutd',
          '123456a',
          'britney',
          'katrina',
          'christina',
          'pasaway',
          'mahal',
          'tatiana',
          'cantik',
          '0123456',
          'teiubesc',
          '147258369',
          'natalia',
          'francisco',
          'amorcito',
          'paola',
          'angelito',
          'manchester',
          'mommy1',
          '147258',
          'amigos',
          'marlon',
          'linkinpark',
          '147852',
          'diego',
          '444444',
          'iverson',
          'andrei',
          'justine',
          'frankie',
          'pimpin',
          'fashion',
          'bestfriend',
          'england',
          'hermosa',
          '456123',
          '102030',
          'sporting',
          'hearts',
          'potter',
          'iloveu2',
          'number1',
          '212121',
          'truelove',
          'jayden',
          'savannah',
          'hottie1',
          'ganda',
          'scotland',
          'ilovehim',
          'shakira',
          'estrellita',
          'brandon1',
          'sweets',
          'familia',
          'love12',
          'omarion',
          'monkeys',
          'loverboy',
          'elijah',
          'ronnie',
          'mamita',
          '999999999',
          'broken',
          'rodrigo',
          'westside',
          'mauricio',
          'amigas',
          'preciosa',
          'shopping',
          'flores',
          'isabella',
          'martinez',
          'elaine',
          'friendster',
          'cheche',
          'gracie',
          'connor',
          'valentina',
          'darling',
          'santos',
          'joanne',
          'fuckyou2',
          'pebbles',
          'sunshine1',
          'gangster',
          'gloria',
          'darkangel',
          'bettyboop',
          'jessica1',
          'cheyenne',
          'dustin',
          'iubire',
          'a123456',
          'purple1',
          'bestfriends',
          'inlove',
          'batista',
          'karla',
          'chacha',
          'marian',
          'sexyme',
          'pogiako',
          'jordan1',
          '010203',
          'daddy1',
          'daddysgirl',
          'billabong',
          'pinky',
          'erika',
          'skater',
          'nenita',
          'tigger1',
          'gatito',
          'lokita',
          'maldita',
          'buttercup',
          'bambam',
          'glitter',
          '123789',
          'sister',
          'zacefron',
          'tokiohotel',
          'loveya',
          'lovebug',
          'bubblegum',
          'marissa',
          'cecilia',
          'lollypop',
          'nicolas',
          'puppies',
          'ariana',
          'chubby',
          'sexybitch',
          'roxana',
          'mememe',
          'susana',
          'baller',
          'hotstuff',
          'carter',
          'babylove',
          'angelina',
          'playgirl',
          'sweet16',
          '012345',
          'bhebhe',
          'marcos',
          'loveme1',
          'milagros',
          'lilmama',
          'beyonce',
          'lovely1',
          'catdog',
          'armando',
          'margarita',
          '151515',
          'loves',
          '202020',
          'gerard',
          'undertaker',
          'amistad',
          'capricorn',
          'delfin',
          'cheerleader',
          'password2',
          'PASSWORD',
          'lizzie',
          'matthew1',
          'enrique',
          'badgirl',
          '141414',
          'dancing',
          'cuteme',
          'amelia',
          'skyline',
          'angeles',
          'janine',
          'carlitos',
          'justme',
          'legolas',
          'michelle1',
          'cinderella',
          'jesuschrist',
          'ilovejesus',
          'tazmania',
          'tekiero',
          'thebest',
          'princesita',
          'lucky7',
          'jesucristo',
          'buddy1',
          'regina',
          'myself',
          'lipgloss',
          'jazmin',
          'rosita',
          'chichi',
          'pangit',
          'mierda',
          '741852963',
          'hernandez',
          'arturo',
          'silvia',
          'melvin',
          'celeste',
          'pussycat',
          'gorgeous',
          'honeyko',
          'mylife',
          'babyboo',
          'loveu',
          'lupita',
          'panthers',
          'hollywood',
          'alfredo',
          'musica',
          'hawaii',
          'sparkle',
          'kristina',
          'sexymama',
          'crazy',
          'scarface',
          '098765',
          'hayden',
          'micheal',
          '242424',
          '0987654321',
          'marisol',
          'jeremiah',
          'mhine',
          'isaiah',
          'lolipop',
          'butterfly1',
          'xbox360',
          'madalina',
          'anamaria',
          'yourmom',
          'jasmine1',
          'bubbles1',
          'beatriz',
          'diamonds',
          'friendship',
          'sweetness',
          'desiree',
          '741852',
          'hannah1',
          'bananas',
          'julius',
          'leanne',
          'marie1',
          'lover1',
          'twinkle',
          'february',
          'bebita',
          '87654321',
          'twilight',
          'imissyou',
          'pollito',
          'ashlee',
          'cookie1',
          '147852369',
          'beckham',
          'simone',
          'nursing',
          'torres',
          'damian',
          '123123123',
          'joshua1',
          'babyface',
          'dinamo',
          'mommy',
          'juliana',
          'cassandra',
          'redsox',
          'gundam',
          '0000',
          'ou812',
          'dave',
          'golf',
          'molson',
          'Monday',
          'newpass',
          'thx1138',
          '1',
          'Internet',
          'coke',
          'foobar',
          'abc',
          'fish',
          'fred',
          'help',
          'ncc1701d',
          'newuser',
          'none',
          'pat',
          'dog',
          'duck',
          'duke',
          'floyd',
          'guest',
          'joe',
          'kingfish',
          'micro',
          'sam',
          'telecom',
          'test1',
          '7777',
          'absolut',
          'babylon5',
          'backup',
          'bill',
          'bird33',
          'deliver',
          'fire',
          'flip',
          'galileo',
          'gopher',
          'hansolo',
          'jane',
          'jim',
          'mom',
          'passwd',
          'phil',
          'phish',
          'porsche911',
          'rain',
          'red',
          'sergei',
          'training',
          'truck',
          'video',
          'volvo',
          '007',
          '1969',
          '5683',
          'Bond007',
          'Friday',
          'Hendrix',
          'October',
          'Taurus',
          'aaa',
          'alexandr',
          'catalog',
          'challenge',
          'clipper',
          'coltrane',
          'cyrano',
          'dan',
          'dawn',
          'dean',
          'deutsch',
          'dilbert',
          'e-mail',
          'export',
          'ford',
          'fountain',
          'fox',
          'frog',
          'gabriell',
          'garlic',
          'goforit',
          'grateful',
          'hoops',
          'lady',
          'ledzep',
          'lee',
          'mailman',
          'mantra',
          'market',
          'mazda1',
          'metallic',
          'ncc1701e',
          'nesbitt',
          'open',
          'pete',
          'quest',
          'republic',
          'research',
          'supra',
          'tara',
          'testing',
          'xanadu',
          'xxxx',
          'zaphod',
          'zeus',
          '0007',
          '1022',
          '10sne1',
          '1973',
          '1978',
          '2000',
          '2222',
          '3bears',
          'Broadway',
          'Fisher',
          'Jeanne',
          'Killer',
          'Knight',
          'Master',
          'Pepper',
          'Sierra',
          'Tennis',
          'abacab',
          'abcd',
          'ace',
          'acropolis',
          'amy',
          'anders',
          'avenir',
          'basil',
          'bass',
          'beer',
          'ben',
          'bliss',
          'blowfish',
          'boss',
          'bridges',
          'buck',
          'bugsy',
          'bull',
          'cannondale',
          'canon',
          'catnip',
          'chip',
          'civil',
          'content',
          'cook',
          'cordelia',
          'crack1',
          'cyber',
          'daisie',
          'dark1',
          'database',
          'deadhead',
          'denali',
          'depeche',
          'dickens',
          'emmitt',
          'entropy',
          'farout',
          'farside',
          'feedback',
          'fidel',
          'firenze',
          'fish1',
          'fletch',
          'fool',
          'fozzie',
          'fun',
          'gargoyle',
          'gasman',
          'gold',
          'graphic',
          'hell',
          'image',
          'intern',
          'intrepid',
          'jeff',
          'jkl123',
          'joel',
          'johanna1',
          'kidder',
          'kim',
          'king',
          'kirk',
          'kris',
          'lambda',
          'leon',
          'logical',
          'lorrie',
          'major',
          'mariner',
          'mark1',
          'max',
          'media',
          'merlot',
          'midway',
          'mine',
          'mmouse',
          'moon',
          'mopar',
          'mortimer',
          'nermal',
          'nina',
          'olsen',
          'opera',
          'overkill',
          'pacers',
          'packer',
          'picard',
          'polar',
          'polo',
          'primus',
          'prometheus',
          'public',
          'radio',
          'rastafarian',
          'reptile',
          'rob',
          'robotech',
          'rodeo',
          'rolex',
          'rouge',
          'roy',
          'ruby',
          'salasana',
          'scarecrow',
          'scout',
          'scuba1',
          'sergey',
          'skibum',
          'skunk',
          'sound',
          'starter',
          'sting1',
          'sunbird',
          'tbird',
          'teflon',
          'temporal',
          'terminal',
          'the',
          'thejudge',
          'time',
          'toby',
          'today',
          'tokyo',
          'tree',
          'trout',
          'vader',
          'val',
          'valhalla',
          'windsurf',
          'wolf',
          'wolf1',
          'xcountry',
          'yoda',
          'yukon',
          '1213',
          '1214',
          '1225',
          '1313',
          '1818',
          '1975',
          '1977',
          '1991',
          '1kitty',
          '2001',
          '2020',
          '2112',
          '2kids',
          '333',
          '4444',
          '5050',
          '57chevy',
          '7dwarfs',
          'Animals',
          'Ariel',
          'Bismillah',
          'Booboo',
          'Boston',
          'Carol',
          'Computer',
          'Creative',
          'Curtis',
          'Denise',
          'Eagles',
          'Esther',
          'Fishing',
          'Freddy',
          'Gandalf',
          'Golden',
          'Goober',
          'Hacker',
          'Harley',
          'Henry',
          'Hershey',
          'Jackson',
          'Jersey',
          'Joanna',
          'Johnson',
          'Katie',
          'Kitten',
          'Liberty',
          'Lindsay',
          'Lizard',
          'Madeline',
          'Margaret',
          'Maxwell',
          'Money',
          'Monster',
          'Pamela',
          'Peaches',
          'Peter',
          'Phoenix',
          'Piglet',
          'Pookie',
          'Rabbit',
          'Raiders',
          'Random',
          'Russell',
          'Sammy',
          'Saturn',
          'Skeeter',
          'Smokey',
          'Sparky',
          'Speedy',
          'Sterling',
          'Theresa',
          'Thunder',
          'Vincent',
          'Willow',
          'Winnie',
          'Wolverine',
          'aaaa',
          'aardvark',
          'abbott',
          'acura',
          'admin',
          'admin1',
          'adrock',
          'aerobics',
          'agent',
          'airwolf',
          'ali',
          'alien',
          'allegro',
          'allstate',
          'altamira',
          'altima1',
          'andrew!',
          'ann',
          'anne',
          'anneli',
          'aptiva',
          'arrow',
          'asdf;lkj',
          'assmunch',
          'baraka',
          'barnyard',
          'bart',
          'bartman',
          'beasty',
          'beavis1',
          'bebe',
          'belgium',
          'beowulf',
          'beryl',
          'best',
          'bharat',
          'bichon',
          'bigal',
          'biker',
          'bilbo',
          'bills',
          'bimmer',
          'biochem',
          'birdy',
          'blinds',
          'blitz',
          'bluejean',
          'bogey',
          'bogus',
          'boulder',
          'bourbon',
          'boxer',
          'brain',
          'branch',
          'britain',
          'broker',
          'bucks',
          'buffett',
          'bugs',
          'bulls',
          'burns',
          'buzz',
          'c00per',
          'calgary',
          'camay',
          'carl',
          'cat',
          'cement',
          'cessna',
          'chad',
          'chainsaw',
          'chameleon',
          'chang',
          'chess',
          'chinook',
          'chouette',
          'chronos',
          'cicero',
          'circuit',
          'cirque',
          'cirrus',
          'clapton',
          'clarkson',
          'class',
          'claudel',
          'cleo',
          'cliff',
          'clock',
          'color',
          'comet',
          'concept',
          'concorde',
          'coolbean',
          'corky',
          'cornflake',
          'corwin',
          'cows',
          'crescent',
          'cross',
          'crowley',
          'cthulhu',
          'cunt',
          'current',
          'cutlass',
          'daedalus',
          'dagger1',
          'daily',
          'dale',
          'dana',
          'daytek',
          'dead',
          'decker',
          'dharma',
          'dillweed',
          'dipper',
          'disco',
          'dixon',
          'doitnow',
          'doors',
          'dork',
          'doug',
          'dutch',
          'effie',
          'ella',
          'elsie',
          'engage',
          'eric1',
          'ernie1',
          'escort1',
          'excel',
          'faculty',
          'fairview',
          'faust',
          'fenris',
          'finance',
          'first',
          'fishhead',
          'flanders',
          'fleurs',
          'flute',
          'flyboy',
          'flyer',
          'franka',
          'frederic',
          'free',
          'front242',
          'frontier',
          'fugazi',
          'funtime',
          'gaby',
          'gaelic',
          'gambler',
          'gammaphi',
          'garfunkel',
          'garth',
          'gary',
          'gateway2',
          'gator1',
          'gibbons',
          'gigi',
          'gilgamesh',
          'goat',
          'godiva',
          'goethe',
          'gofish',
          'good',
          'gramps',
          'gravis',
          'gray',
          'greed',
          'greg',
          'greg1',
          'greta',
          'gretzky',
          'guido',
          'gumby',
          'h2opolo',
          'hamid',
          'hank',
          'hawkeye1',
          'health1',
          'hello8',
          'help123',
          'helper',
          'homerj',
          'hoosier',
          'hope',
          'huang',
          'hugo',
          'hydrogen',
          'ib6ub9',
          'insight',
          'instructor',
          'integral',
          'iomega',
          'iris',
          'izzy',
          'jazz',
          'jean',
          'jeepster',
          'jetta1',
          'joanie',
          'josee',
          'joy',
          'julia2',
          'jumbo',
          'jump',
          'justice4',
          'kalamazoo',
          'kali',
          'kat',
          'kate',
          'kerala',
          'kids',
          'kiwi',
          'kleenex',
          'kombat',
          'lamer',
          'laser',
          'laserjet',
          'lassie1',
          'leblanc',
          'legal',
          'leo',
          'life',
          'lions',
          'liz',
          'logger',
          'logos',
          'loislane',
          'loki',
          'longer',
          'lori',
          'lost',
          'lotus',
          'lou',
          'macha',
          'macross',
          'madoka',
          'makeitso',
          'mallard',
          'marc',
          'math',
          'mattingly',
          'mechanic',
          'meister',
          'mercer',
          'merde',
          'merrill',
          'michal',
          'michou',
          'mickel',
          'minou',
          'mobydick',
          'modem',
          'mojo',
          'montana3',
          'montrose',
          'motor',
          'mowgli',
          'mulder1',
          'muscle',
          'neil',
          'neutrino',
          'newaccount',
          'nicklaus',
          'nightshade',
          'nightwing',
          'nike',
          'none1',
          'nopass',
          'nouveau',
          'novell',
          'oaxaca',
          'obiwan',
          'obsession',
          'orville',
          'otter',
          'ozzy',
          'packrat',
          'paint',
          'papa',
          'paradigm',
          'pass',
          'pavel',
          'peterk',
          'phialpha',
          'phishy',
          'piano1',
          'pianoman',
          'pianos',
          'pipeline',
          'plato',
          'play',
          'poetic',
          'print',
          'printing',
          'provider',
          'qqq111',
          'quebec',
          'qwer',
          'racer',
          'racerx',
          'radar',
          'rafiki',
          'raleigh',
          'rasta1',
          'redcloud',
          'redfish',
          'redwing',
          'redwood',
          'reed',
          'rene',
          'reznor',
          'rhino',
          'ripple',
          'rita',
          'robocop',
          'robotics',
          'roche',
          'roni',
          'rossignol',
          'rugger',
          'safety1',
          'saigon',
          'satori',
          'saturn5',
          'schnapps',
          'scotch',
          'scuba',
          'secret3',
          'seeker',
          'services',
          'sex',
          'shanghai',
          'shazam',
          'shelter',
          'sigmachi',
          'signal',
          'signature',
          'simsim',
          'skydive',
          'slick',
          'smegma',
          'smiths',
          'smurfy',
          'snow',
          'sober1',
          'sonics',
          'sony',
          'spazz',
          'sphynx',
          'spock',
          'spoon',
          'spot',
          'sprocket',
          'starbuck',
          'steel',
          'stephi',
          'sting',
          'stocks',
          'storage',
          'strat',
          'strato',
          'stud',
          'student2',
          'susanna',
          'swanson',
          'swim',
          'switzer',
          'system5',
          't-bone',
          'talon',
          'tarheel',
          'tata',
          'tazdevil',
          'tester',
          'testtest',
          'thisisit',
          'thorne',
          'tightend',
          'tim',
          'tom',
          'tool',
          'total',
          'toucan',
          'transfer',
          'transit',
          'transport',
          'trapper',
          'trash',
          'trophy',
          'tucson',
          'turbo2',
          'unity',
          'upsilon',
          'vedder',
          'vette',
          'vikram',
          'virago',
          'visual',
          'volcano',
          'walden',
          'waldo',
          'walleye',
          'webmaster',
          'wedge',
          'whale1',
          'whit',
          'whoville',
          'wibble',
          'will',
          'wombat1',
          'word',
          'world',
          'x-files',
          'xxx123',
          'zack',
          'zepplin',
          'zoltan',
          'zoomer',
          '123go',
          '21122112',
          '5555',
          '911',
          'FuckYou',
          'Fuckyou',
          'Gizmo',
          'Hello',
          'Michel',
          'Qwerty',
          'Windows',
          'angus',
          'aspen',
          'ass',
          'bird',
          'booster',
          'byteme',
          'cats',
          'changeit',
          'christia',
          'christoph',
          'classroom',
          'cloclo',
          'corrado',
          'dasha',
          'fiction',
          'french1',
          'fubar',
          'gator',
          'gilles',
          'gocougs',
          'hilbert',
          'hola',
          'home',
          'judy',
          'koko',
          'lulu',
          'mac',
          'macintosh',
          'mailer',
          'mars',
          'meow',
          'ne1469',
          'niki',
          'paul',
          'politics',
          'pomme',
          'property',
          'ruth',
          'sales',
          'salut',
          'scrooge',
          'skidoo',
          'spain',
          'surf',
          'sylvie',
          'symbol',
          'forum',
          'rotimi',
          'god',
          'saved',
          '2580',
          '1998',
          'xxx',
          '1928',
          '777',
          'info',
          'a',
          'netware',
          'sun',
          'tech',
          'doom',
          'mmm',
          'one',
          'ppp',
          '1911',
          '1948',
          '1996',
          '5252',
          'Champs',
          'Tuesday',
          'bach',
          'crow',
          'don',
          'draft',
          'hal9000',
          'herzog',
          'huey',
          'jethrotull',
          'jussi',
          'mail',
          'miki',
          'nicarao',
          'snowski',
          '1316',
          '1412',
          '1430',
          '1952',
          '1953',
          '1955',
          '1956',
          '1960',
          '1964',
          '1qw23e',
          '22',
          '2200',
          '2252',
          '3010',
          '3112',
          '4788',
          '6262',
          'Alpha',
          'Bastard',
          'Beavis',
          'Cardinal',
          'Celtics',
          'Cougar',
          'Darkman',
          'Figaro',
          'Fortune',
          'Geronimo',
          'Hammer',
          'Homer',
          'Janet',
          'Mellon',
          'Merlot',
          'Metallic',
          'Montreal',
          'Newton',
          'Paladin',
          'Peanuts',
          'Service',
          'Vernon',
          'Waterloo',
          'Webster',
          'aki123',
          'aqua',
          'aylmer',
          'beta',
          'bozo',
          'car',
          'chat',
          'chinacat',
          'cora',
          'courier',
          'dogbert',
          'eieio',
          'elina1',
          'fly',
          'funguy',
          'fuzz',
          'ggeorge',
          'glider1',
          'gone',
          'hawk',
          'heikki',
          'histoire',
          'hugh',
          'if6was9',
          'ingvar',
          'jan',
          'jedi',
          'jimi',
          'juhani',
          'khan',
          'lima',
          'midvale',
          'neko',
          'nesbit',
          'nexus6',
          'nisse',
          'notta1',
          'pam',
          'park',
          'pole',
          'pope',
          'pyro',
          'ram',
          'reliant',
          'rex',
          'rush',
          'seoul',
          'skip',
          'stan',
          'sue',
          'suzy',
          'tab',
          'testi',
          'thelorax',
          'tika',
          'tnt',
          'toto1',
          'tre',
          'wind',
          'x-men',
          'xyz',
          'zxc',
          '369',
          'Abcdef',
          'Asdfgh',
          'Changeme',
          'NCC1701',
          'Zxcvbnm',
          'demo',
          'doom2',
          'e',
          'good-luck',
          'homebrew',
          'm1911a1',
          'nat',
          'ne1410s',
          'ne14a69',
          'zhongguo',
          'sample123',
          '0852',
          'basf',
          'OU812',
          '!@#$%',
          'informix',
          'majordomo',
          'news',
          'temp',
          'trek',
          '!@#$%^',
          '!@#$%^&*',
          'Pentium',
          'Raistlin',
          'adi',
          'bmw',
          'law',
          'm',
          'new',
          'opus',
          'plus',
          'visa',
          'www',
          'y',
          'zzz',
          '1332',
          '1950',
          '3141',
          '3533',
          '4055',
          '4854',
          '6301',
          'Bonzo',
          'ChangeMe',
          'Front242',
          'Gretel',
          'Michel1',
          'Noriko',
          'Sidekick',
          'Sverige',
          'Swoosh',
          'Woodrow',
          'aa',
          'ayelet',
          'barn',
          'betacam',
          'biz',
          'boat',
          'cuda',
          'doc',
          'hal',
          'hallowell',
          'haro',
          'hosehead',
          'i',
          'ilmari',
          'irmeli',
          'j1l2t3',
          'jer',
          'kcin',
          'kerrya',
          'kissa2',
          'leaf',
          'lissabon',
          'mart',
          'matti1',
          'mech',
          'morecats',
          'paagal',
          'performa',
          'prof',
          'ratio',
          'ship',
          'slip',
          'stivers',
          'tapani',
          'targas',
          'test2',
          'test3',
          'tula',
          'unix',
          'user1',
          'xanth',
          '!@#$%^&',
          '1701d',
          '@#$%^&',
          'Qwert',
          'allo',
          'dirk',
          'go',
          'newcourt',
          'nite',
          'notused',
          'sss']

def DictionaryAttack(passwordfile, oZipfile, fOut, stop):
    try:
        oZipfile.open(oZipfile.infolist()[0], 'r').read(2)
        if stop:
            Print('ZIP file is not password protected', fOut)
        return ''
    except RuntimeError:
        pass

    counter = 0
    passwords = GetDictionary(passwordfile)
    start = time.time()
    for password in passwords:
        try:
            oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(password)).read(2)
            if stop:
                Print('Password: %s' % password, fOut)
            return password
        except KeyboardInterrupt:
            return None
        except RuntimeError:
            pass
        except zipfile.BadZipfile:
            pass
        except zlib.error:
            pass
        counter += 1
        if counter % 10000 == 0:
            pps = float(counter) / float(time.time() - start)
            if stop:
                Print('Passwords: %8d %.2f%% p/s: %d ETC: %s' % (counter, float(counter) / float(len(passwords)) * 100.0, pps, FormatTime(start + len(passwords) / pps)), fOut)
    return None

def SelectDumpFunction(options):
    if options.dump or options.dumpall:
        DumpFunction = lambda x:x
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    elif options.hexdump or options.hexdumpall:
        DumpFunction = HexDump
    elif options.translate != '':
        DumpFunction = Translate(options.translate)
    else:
        DumpFunction = HexAsciiDump
    return DumpFunction

def ZIPDump(zipfilename, options, data=None):
    global decoders
    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    FixPipe()
    if data != None:
        oZipfile = CreateZipFileObject(DataIO(data), 'r')
    elif zipfilename == '':
        if sys.platform == 'win32':
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        if sys.version_info[0] > 2:
            oZipfile = CreateZipFileObject(DataIO(sys.stdin.buffer.read()), 'r')
        else:
            oZipfile = CreateZipFileObject(DataIO(sys.stdin.read()), 'r')
    else:
        oZipfile = CreateZipFileObject(zipfilename, 'r')
    zippassword = options.password
    if not options.regular and len(oZipfile.infolist()) == 1:
        try:
            if oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(zippassword)).read(2) == b'PK':
                oZipfile2 = CreateZipFileObject(DataIO(oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(zippassword)).read()), 'r')
                oZipfile.close()
                oZipfile = oZipfile2
        except:
            pass

    if options.output:
        fOut = open(options.output, 'w')
    else:
        fOut = None

    if options.jsonoutput:
        object = []
        counter = 1
        for oZipInfo in oZipfile.infolist():
            file = oZipfile.open(oZipInfo, 'r', C2BIP3(zippassword))
            filecontent = file.read()
            file.close()
            object.append({'id': counter, 'name': oZipInfo.filename, 'content': binascii.b2a_base64(filecontent).decode().strip('\n')})
            counter += 1
        Print(json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': object}), fOut)
        if fOut:
            fOut.close()
        oZipfile.close()
        return

    if options.passwordfile != '':
        passwordfound = DictionaryAttack(options.passwordfile, oZipfile, fOut, False)
        if passwordfound != None:
            zippassword = passwordfound
    elif options.passwordfilestop != '':
        DictionaryAttack(options.passwordfilestop, oZipfile, fOut, True)
        if fOut:
            fOut.close()
        return

    if options.yara != None:
        if not 'yara' in sys.modules:
            print('Error: option yara requires the YARA Python module.')
            return
        rules = YARACompile(options.yara)

    if options.dump or options.dumpall or options.hexdump or options.hexdumpall or options.asciidump or options.asciidumpall or options.translate != '':
        DumpFunction = SelectDumpFunction(options)
        counter = 0
        for oZipInfo in oZipfile.infolist():
            counter += 1
            if DecideToSelect(options.select, counter, oZipInfo.filename):
                file = oZipfile.open(oZipInfo, 'r', C2BIP3(zippassword))
                if options.output:
                    fOut.write(DumpFunction(CutData(file.read(), options.cut)))
                else:
                    StdoutWriteChunked(DumpFunction(CutData(file.read(), options.cut)))
                file.close()
                if options.select == '' and (options.dump or options.hexdump or options.asciidump):
                    break
    else:
        if oZipfile.comment != b'':
            Print(oZipfile.comment, fOut)
        outputRows = []
        outputExtraInfo = ['']
        headers = ['Index']
        if options.zipfilename:
            headers.append('Zipfilename')
        headers.append('Filename')
        if options.yara:
            headers.extend(['Decoder', 'YARA namespace', 'YARA rule'])
        else:
            if options.extended:
                headers.extend(['Encrypted', 'Timestamp', 'MD5', 'Filesize', 'Entropy', 'Unique bytes', 'Magic HEX', 'Magic ASCII', 'Null bytes', 'Control bytes', 'Whitespace bytes', 'Printable bytes', 'High bytes'])
            else:
                headers.extend(['Encrypted', 'Timestamp'])
        if not options.yarastringsraw:
            outputRows.append(headers)
        counter = 0
        for oZipInfo in oZipfile.infolist():
            counter += 1
            if DecideToSelect(options.select, counter, oZipInfo.filename):
                file = oZipfile.open(oZipInfo, 'r', C2BIP3(zippassword))
                filecontent = file.read()
                file.close()
                encrypted = oZipInfo.flag_bits & 1
                timestamp = '%04d-%02d-%02d %02d:%02d:%02d' % oZipInfo.date_time
                if options.yara == None:
                    if options.extended:
                        filehash, magicPrintable, magicHex, fileSize, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateFileMetaData(filecontent)
                        row = [oZipInfo.filename, encrypted, timestamp, filehash, fileSize, entropy, countUniqueBytes, magicHex, magicPrintable, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes]
                    else:
                        row = [oZipInfo.filename, encrypted, timestamp]
                    if options.zipfilename:
                        row.insert(0, zipfilename)
                    row.insert(0, counter)
                    outputRows.append(row)
                    outputExtraInfo.append(GenerateExtraInfo(options.extra, counter, zipfilename, oZipInfo.filename, encrypted, timestamp, filecontent))
                else:
                    oDecoders = [cIdentity(filecontent, None)]
                    for cDecoder in decoders:
                        try:
                            oDecoder = cDecoder(filecontent, options.decoderoptions)
                            oDecoders.append(oDecoder)
                        except Exception as e:
                            print('Error instantiating decoder: %s' % cDecoder.name)
                            if options.verbose:
                                raise e
                            return
                    for oDecoder in oDecoders:
                        while oDecoder.Available():
                            for result in rules.match(data=oDecoder.Decode()):
                                if options.yarastringsraw:
                                    for stringdata in result.strings:
                                        outputExtraInfo.append('')
                                        outputRows.append([stringdata[2]])
                                else:
                                    row = [oZipInfo.filename, oDecoder.Name(), result.namespace, result.rule]
                                    if options.zipfilename:
                                        row.insert(0, zipfilename)
                                    row.insert(0, counter)
                                    if options.yarastrings:
                                        for stringdata in result.strings:
                                            row.append('%06x' % stringdata[0])
                                            row.append(stringdata[1])
                                            row.append(binascii.hexlify(stringdata[2]))
                                            row.append(repr(stringdata[2]))
                                    outputExtraInfo.append('')
                                    outputRows.append(row)

        PrintOutput(outputRows, outputExtraInfo, options.extra, options.separator, QUOTE, fOut)

    if fOut:
        fOut.close()
    oZipfile.close()

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

#a# todo: add more record types - https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
def ParseZIPRecord(data):
    if data[0:2] != b'PK':
        return None
    magic = 'PK'
    extra = None
    if len(data) >= 4:
        magic += '%02x%02x' % (P23Ord(data[2]), P23Ord(data[3]))
        if data[2:4] == b'\x03\x04':
            magic += ' fil'
            if len(data[26:28]) == 2:
                length = struct.unpack('<H', data[26:28])[0]
                filename = data[30:30 + length]
                if len(filename) == length:
                    magic += ' ' + repr(filename)
        elif data[2:4] == b'\x01\x02':
            magic += ' dir'
            if len(data[28:30]) == 2:
                length = struct.unpack('<H', data[28:30])[0]
                filename = data[46:46 + length]
                if len(filename) == length:
                    magic += ' ' + repr(filename)
        elif data[2:4] == b'\x05\x06':
            magic += ' end'
            if len(data[20:22]) == 2:
                length = struct.unpack('<H', data[20:22])[0]
                extra = 22 + length
            else:
                extra = len(data)
        elif data[2:4] == b'\x07\x08':
            magic += ' dsc'
        else:
            return None
    return magic, extra

def AnalyzeZIPRecord(data, options):
    DumpFunction = SelectDumpFunction(options)

    if data[0:2] != b'PK':
        print('This is not a PKZIP record')
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return

    data = data[2:]
    if data[:2] != b'\x05\x06':
        print('This is not a PKZIP end-of-central-directory record')
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return

    print('EOCD (End Of Central Directory) record: PK\\x05\\x06')

    data = data[2:]

    formatstringH = '<H'
    formatlengthH = struct.calcsize(formatstringH)
    formatstringI = '<I'
    formatlengthI = struct.calcsize(formatstringI)

    if len(data) < formatlengthH:
        print(' Incomplete disk number field, missing %d byte(s)' % (formatlengthH - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Disk number field: %d' % struct.unpack(formatstringH, data[:formatlengthH])[0])

    data = data[formatlengthH:]
    if len(data) < formatlengthH:
        print(' Incomplete start disk number field, missing %d byte(s)' % (formatlengthH - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Start disk number field: %d' % struct.unpack(formatstringH, data[:formatlengthH])[0])

    data = data[formatlengthH:]
    if len(data) < formatlengthH:
        print(' Incomplete entries on disk field, missing %d byte(s)' % (formatlengthH - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Entries on disk field: %d' % struct.unpack(formatstringH, data[:formatlengthH])[0])

    data = data[formatlengthH:]
    if len(data) < formatlengthH:
        print(' Incomplete entries in directory field, missing %d byte(s)' % (formatlengthH - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Entries in directory field: %d' % struct.unpack(formatstringH, data[:formatlengthH])[0])

    data = data[formatlengthH:]
    if len(data) < formatlengthI:
        print(' Incomplete directory size field, missing %d byte(s)' % (formatlengthI - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Directory size field: %d' % struct.unpack(formatstringI, data[:formatlengthI])[0])

    data = data[formatlengthI:]
    if len(data) < formatlengthI:
        print(' Incomplete directory offset field, missing %d byte(s)' % (formatlengthI - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        directoryOffset = struct.unpack(formatstringI, data[:formatlengthI])[0]
        print(' Directory offset field: %d (0x%08x)' % (directoryOffset, directoryOffset))

    data = data[formatlengthI:]
    if len(data) < formatlengthH:
        print(' Incomplete comment length field, missing %d byte(s)' % (formatlengthH - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        commentLength = struct.unpack(formatstringH, data[:formatlengthH])[0]
        print(' Comment length field: %d' % commentLength)

    if commentLength == 0:
        return

    data = data[formatlengthH:]
    if len(data) < commentLength:
        print(' Incomplete comment field, missing %d byte(s)' % (commentLength - len(data)))
        StdoutWriteChunked(DumpFunction(CutData(data, options.cut)))
        return
    else:
        print(' Comment field: %s' % repr(data[:commentLength]))

def ZIPFind(zipfilename, options):
    data = cBinaryFile(zipfilename, C2BIP3(options.password), True, True).read()
    locations = [entry for entry in [[location, ParseZIPRecord(data[location:])] for location in FindAll(data, b'PK')] if entry[1] != None]
    records = []
    index = 1
    if len(locations) > 0 and locations[0][0] != 0:
        records.append(['p', 0, 'data', locations[0][0]])
    for location, info in locations:
        if info[0] == 'PK0506 end':
            records.append([index, location, info[0], info[1]])
            index += 1
        else:
            records.append([-1, location, info[0], info[1]])
    if len(locations) > 0 and locations[-1][1][1] != None and locations[-1][0] + locations[-1][1][1] < len(data):
        records.append(['s', locations[-1][0] + locations[-1][1][1], 'data', len(data) - locations[-1][0] - locations[-1][1][1]])
    if options.find == 'list':
        index = 1
        overview = []
        for index, location, record, info in records:
            if index in ['p', 's']:
                print(' %3s 0x%08x %s %d:%dl' % (index, location, record, location, info))
            else:
                if record == 'PK0506 end' and info < 22:
                    print(' %3s 0x%08x %s %d byte(s) missing' % ('' if index < 0 else str(index), location, record, 22 - info))
                else:
                    print(' %3s 0x%08x %s' % ('' if index < 0 else str(index), location, record))
    elif options.find in ['p', 's']:
        DumpFunction = SelectDumpFunction(options)
        partial = None
        for index, location, record, info in records:
            if options.find == index:
                partial = data[location:location + info]
        if partial == None:
            print('Index not found')
        elif options.output:
            with open(options.output, 'wb' if options.dump or options.dumpall else 'w') as fOut:
                fOut.write(DumpFunction(CutData(partial, options.cut)))
        else:
            StdoutWriteChunked(DumpFunction(CutData(partial, options.cut)))
    else:
        index = int(options.find)
        eocd = None
        for record in records:
            if record[0] == index:
                eocd = record
        if eocd == None:
            print('Index not found')
        elif options.info:
            AnalyzeZIPRecord(data[eocd[1]:], options)
        else:
            ZIPDump(zipfilename, options, data[:eocd[1] + eocd[3]])

def ValidateOptions(options):
    if ParseCutArgument(options.cut)[0] == None:
        print('Error: the expression of the cut option (-c) is invalid: %s' % options.cut)
        return True

    if options.find != '':
        if options.find.lower() in ['l', 'list']:
            options.find = 'list'
        elif options.find.lower() in ['p', 's']:
            options.find = options.find.lower()
        else:
            try:
                number = int(options.find)
                if number < 1:
                    print('Error: the value of the find option (-f) is invalid, it should be at least 1: %s' % options.find)
                    return True
            except:
                print('Error: the value of the find option (-f) is invalid: %s' % options.find)
                return True

    return False

def OptionsEnvironmentVariables(options):
    if options.extra == '':
        options.extra = os.getenv('ZIPDUMP_EXTRA', options.extra)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [zipfile]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default='', help='select index nr or name')
    oParser.add_option('-S', '--separator', default='', help='Separator character (default )')
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump of first file or selected file')
    oParser.add_option('-D', '--dumpall', action='store_true', default=False, help='perform dump of all files or selected file')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump of first file or selected file')
    oParser.add_option('-X', '--hexdumpall', action='store_true', default=False, help='perform hex dump of all files or selected file')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump of first file or selected file')
    oParser.add_option('-A', '--asciidumpall', action='store_true', default=False, help='perform ascii dump of all files or selected file')
    oParser.add_option('-t', '--translate', type=str, default='', help='string translation, like utf16 or .decode("utf8")')
    oParser.add_option('-e', '--extended', action='store_true', default=False, help='report extended information')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-P', '--passwordfile', default='', help='A file with ZIP passwords to be used in a dictionary attack; use . to use build-in list')
    oParser.add_option('--passwordfilestop', default='', help='A file with ZIP passwords to be used in a dictionary attack, stop after the attack; use . to use build-in list')
    oParser.add_option('-y', '--yara', help="YARA rule file (or directory or @file) to check files (YARA search doesn't work with -s option)")
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('--yarastringsraw', action='store_true', default=False, help='Print only YARA strings')
    oParser.add_option('-C', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-c', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-r', '--regular', action='store_true', default=False, help='if the ZIP file contains a single ZIP file, handle it like a regular (non-ZIP) file')
    oParser.add_option('-z', '--zipfilename', action='store_true', default=False, help='include the filename of the ZIP file in the output')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: ZIPDUMP_EXTRA)')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('-f', '--find', type=str, default='', help='Find PK MAGIC sequence (use l or list for listing, number for selecting)')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='display extra info')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if ValidateOptions(options):
        return 0

    OptionsEnvironmentVariables(options)

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif len(args) == 0:
        if options.find == '':
            ZIPDump('', options)
        else:
            ZIPFind('', options)
    else:
        if options.find == '':
            ZIPDump(args[0], options)
        else:
            ZIPFind(args[0], options)

if __name__ == '__main__':
    Main()
