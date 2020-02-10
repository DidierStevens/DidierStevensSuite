#!/usr/bin/env python

__description__ = 'This is essentialy a wrapper for the struct module'
__author__ = 'Didier Stevens'
__version__ = '0.0.13'
__date__ = '2020/02/04'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/12/03: start
  2017/06/16: refactoring to cBinaryFile
  2017/07/11: added CutData
  2017/11/04: 0.0.2 refactoring; continued; added options -c & -s
  2017/11/18: added option -f
  2017/12/01: updated FilenameCheckHash to handle empty file: #
  2017/12/10: added manual
  2017/12/16: 0.0.3 added epoch to option -f
  2017/12/16: 0.0.4 added representation to option -f
  2017/12/17: continue
  2018/01/02: added extra info for strings when option -f is used
  2018/01/15: tweaking string output when option -f is used
  2018/01/19: updated man
  2018/02/15: 0.0.5 added remainder for option -f
  2018/02/18: added option -j
  2018/02/19: changed option -j to --jsoninput
  2018/02/23: added * remainder to option -f
  2018/02/24: updated man
  2018/02/26: changed options -c and -s to -C and -S, added options -s -a -x -d, updated man
  2018/03/05: updated #e# expressions
  2018/06/12: updated man
  2018/06/17: added property extracted to cBinaryFile
  2018/07/21: updated CheckJSON
  2018/10/28: 0.0.6 added option -n
  2018/11/09: 0.0.7 added X and S representation for strings; option -A
  2018/12/08: updated ParseCutArgument; added selection warning
  2019/03/22: 0.0.8 added -F option
  2019/03/25: added library & -f name= ; added select remainder (-s r)
  2019/04/18: added FiletimeUTC; added support for annotations to library files
  2019/07/15: 0.0.9 added tlv format parsing
  2019/11/03: 0.0.10 added bitstream support
  2019/11/08: added multibits for bitstream
  2020/01/20: 0.0.11 added ParsePackExpression #p#; added OID
  2020/01/24: added #h# support for spaces; bugfix #e#chr
  2020/01/25: added DSS_DEFAULT_HASH_ALGORITHMS; Python 3 fixes
  2020/01/26: 0.0.12 ParsePackExpression replaced eval with int
  2020/02/04: 0.0.13 added suffix for tlv; added support to -s for multiple selection; added j:b for bitstream

Todo:
"""

import optparse
import sys
import os
import zipfile
import binascii
import random
import gzip
import collections
import glob
import textwrap
import re
import struct
import string
import math
import time
import hashlib
import json
import datetime
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO

def PrintManual():
    manual = r'''
Manual:

This tool is essentialy a wrapper for the Python module struct.

It reads one or more files or stdin and parses the content according to different formats. This tool is very versatile when it comes to handling files, later full details will be provided.

This Python script was developed with Python 2.7 and tested with Python 2.7 and 3.5.

Example:

format-bytes.py random.bin
File: random.bin
s:signed u:unsigned l:little-endian b:big-endian m:mixed-endian
1I: s -69 u 187
2I: sl 26043 ul 26043 sb -17563 ub 47973
4I: sl 881419707 ul 881419707 sb -1150973644 ub 3143993652
4F: l 0.000000 b -0.003502
4N: b 187.101.137.52 l 52.137.101.187
4E: l 1997/12/06 14:48:27 b 2069/08/17 19:34:12
8I: sl -3535861847371979333 ul 14910882226337572283 sb -4943394157892145458 ub 13503349915817406158
8T: ul N/A ub N/A
8F: l -1661678170725283018588028971660576297715302893638508902075603349019820032.000000 b -0.000000
16G: b BB658934-6218-EECE-3AC3-179F6B7428FB m {348965BB-1862-CEEE-3AC3-179F6B7428FB}

By default, format-bytes.py reads the first 16 bytes (if available) of the file(s) provided as argument, and parses these bytes as:
 Integer: I
 Float: F
 IPv4 address: N
 epoch: E
 FILETIME: T
 GUID: G

1I is a 8-bit integer, 2I is a 16-bit integer, ...

Bytes are interpreted in little-endian (l), big-endian (b) and mixed-endian (m) format. Mixed-endian is only used for GUIDs (G).
Integers can be signed (s) or unsigned (u).

Use option -f to specify how bytes should be parsed: this option takes a Python struct format string.
Example:

format-bytes.py -f "<hib" random.bin
File: random.bin
 1:    <type 'int'>      26043       65bb  1970/01/01 07:14:03
 2:    <type 'int'>  409089161   18623489  1982/12/18 19:52:41
 3:    <type 'int'>        -18        -12

String lengths can also be specified in hexadecimal by using prefix 0x. For example, 16s, a 16 character long string, can also be specified as 0x10s in hexadecimal.

End the format string with character * to display remaining bytes.
Example:

format-bytes.py -f "<hib*" random.bin
File: random.bin
 1:    <type 'int'>      26043       65bb  1970/01/01 07:14:03
 2:    <type 'int'>  409089161   18623489  1982/12/18 19:52:41
 3:    <type 'int'>        -18        -12
Remainder: 9
00000000: CE 3A C3 17 9F 6B 74 28  FB                       .:...kt(.

1I: s -50 u 206
2I: sl 15054 ul 15054 sb -12742 ub 52794
4I: sl 398670542 ul 398670542 sb -835009769 ub 3459957527
4F: l 0.000000 b -783336896.000000
4N: b 206.58.195.23 l 23.195.58.206
4E: l 1982/08/20 05:49:02 b 2079/08/22 19:18:47
8I: sl 2915073189858196174 ul 2915073189858196174 sb -3586339647020895192 ub 14860404426688656424
8T: ul N/A ub N/A
8F: l 0.000000 b -721504228050136948830706706079286975060186906491372824967789492043776.000000

You can also specify how the parsed bytes should be represented. To achieve this, append a double colon character (:) to the format string followed by a representation character for each member.
Valid representation characters are X (for hexadecimal), I (for integer), E (for epoch), T (for FILETIME) and S (for string with escaped characters).
Example:

C:\Demo>format-bytes.py -f "<hib*:XEI" random.bin
File: random.bin
 1:    <type 'int'>       65bb
 2:    <type 'int'> 1982/12/18 19:52:41
 3:    <type 'int'>        -18
Remainder: 9
00000000: CE 3A C3 17 9F 6B 74 28  FB                       .:...kt(.

1I: s -50 u 206
2I: sl 15054 ul 15054 sb -12742 ub 52794
4I: sl 398670542 ul 398670542 sb -835009769 ub 3459957527
4F: l 0.000000 b -783336896.000000
4N: b 206.58.195.23 l 23.195.58.206
4E: l 1982/08/20 05:49:02 b 2079/08/22 19:18:47
8I: sl 2915073189858196174 ul 2915073189858196174 sb -3586339647020895192 ub 14860404426688656424
8T: ul N/A ub N/A
8F: l 0.000000 b -721504228050136948830706706079286975060186906491372824967789492043776.000000

For strings, the output will include string length, ASCII representation of the string (first 10 bytes), hexadecimal representation (first 10 bytes), entropy and MD5 hash.
By default, it's the MD5 hash, but this can be changed by setting environment variable DSS_DEFAULT_HASH_ALGORITHMS.
Like this: set DSS_DEFAULT_HASH_ALGORITHMS=SHA256

C:\Demo>format-bytes.py -f "<h14s" random.bin
File: random.bin
 1:    <type 'int'>      26043       65bb  1970/01/01 07:14:03
 2:    <type 'str'>         14 .4b...:... 89346218eece3ac3179f 3.807355 e1647bd9711cdfee7959dee4ff956590

Strings can be selected with option -s for dumping. Default is ASCII dump (-a), but run-length encoded ASCII (-A), hexadecimal (-x) and binary (-d) dump is available too.
The remainder can also be selected: -s r.
Selecting several strings is allowed with a range, for example: -s 3-6.

Annotations can be added to particular members, using option -n. Like in this example:

C:\Demo>format-bytes.py -f "<hib*:XEI" -n "2: Creation date 3: Temperature" random.bin
File: random.bin
 1:    <type 'int'>       65bb
 2:    <type 'int'> 1982/12/18 19:52:41 Creation date
 3:    <type 'int'>        -18 Temperature
Remainder: 9
00000000: CE 3A C3 17 9F 6B 74 28  FB                       .:...kt(.

1I: s -50 u 206
2I: sl 15054 ul 15054 sb -12742 ub 52794
4I: sl 398670542 ul 398670542 sb -835009769 ub 3459957527
4F: l 0.000000 b -783336896.000000
4N: b 206.58.195.23 l 23.195.58.206
4E: l 1982/08/20 05:49:02 b 2079/08/22 19:18:47
8I: sl 2915073189858196174 ul 2915073189858196174 sb -3586339647020895192 ub 14860404426688656424
8T: ul N/A ub N/A
8F: l 0.000000 b -721504228050136948830706706079286975060186906491372824967789492043776.000000

This tool can also parse TLV records (Type, Length Value). To achieve this, start the format specifier with tlv= and provide values for format (f:), type (t:), length (l:) and suffix (s:) separated by a comma (,).
Like this example:

C:\Demo>format-bytes.py -f "tlv=f:<III,t:0,l:2" registry.blob.bin
File: registry.blob.bin
 1:     0x59    18 'R\x00S\x00A\x00/\x00S\x00H\x00A\x001\x0
 2:     0x0f    20 'N\x94\xf8r\xf8\x02D\x1e-\x1c\x86\xc4\x0
 3:     0x14    20 'F\xcc\x93\x96\xe7\x14k\xaaW\xc7\xc3\r8\
 4:     0x02   188 '\x1c\x00\x00\x00\\\x00\x00\x00\x0c\x00\
 5:     0x03    20 "\x1c\x9c\xa83\x865\xf1}B\xe4\x1b\x90RH'
 6:     0x04    16 "\x86\xae\xa6J'\x19\xc5\xa0\x05\x8a7\x93
 7:     0x19    16 "\xa5\x9d~\x05\x03';\x01\x90\xd7fF\xbdd\
 8:     0x20   735 '0\x82\x02\xdb0\x82\x01\xc3\xa0\x03\x02\

This command parses the binary blob of a certificate found inside the Windows registry. Each record consists of 3 little-endian 32-bit integers (<III) followed by data. The first integer (index 0), the PropID, is the type (t:0) and the third integer (index 2) is the length (l:2). This is the length of the value (data).

Suffix s: is optional and is a format specifier (like f:) in case the TLV record format to parse has one or more fields after the data.
This for example the case with chunks in PNG files:

C:\Demo>format-bytes.py -f "tlv=f:>II,l:0,t:1,s:<I" #c#8: image.png
File: image.png
 1: 0x49484452    13 '\x00\x00\x01\xb2\x00\x00\x01p\x08\x06\x
 2: 0x70485973     9 '\x00\x00\x0e\xc4\x00\x00\x0e\xc4\x01'
 3: 0x74494d45     7 '\x07\xe4\x01\x04\x14*\x19'
 4: 0x74455874     7 'Author\x00'
 5: 0x74455874    12 'Description\x00'
 6: 0x74455874    10 'Copyright\x00'
 7: 0x74455874    14 'Creation time\x00'
 8: 0x74455874     9 'Software\x00'
 9: 0x74455874    11 'Disclaimer\x00'
10: 0x74455874     8 'Warning\x00'
11: 0x74455874     7 'Source\x00'
12: 0x74455874     8 'Comment\x00'
13: 0x74455874     6 'Title\x00'
14: 0x49444154  4661 'x\x9c\xed\xddQz\xe36\xb2\x06P\xe8~\xb3\
15: 0x49454e44     0 ''

This tool can also extract single bits and join them into a bitstream. To achieve this, start the format specifier with bitstream= and provide values for format (f:), bits (b:) and join (j:) separated by a comma (,).
Like this example:

C:\Demo>format-bytes.py -f "bitstream=f:<H,b:0,j:<" stego.wav

The bytes in file stego.wav are parsed as little-endian, unsigned 16-bit integers (<H) because of format specifier f:<H.
For each integer, the least significant bit is taken (bits specifier b:0) and then joined into bytes from least significant bit to most significant bit (join specifier j:<).

:b can take several bit positions, separated by ;, like this: b:0;1.
:j can be <, > or b. Value b will output a bitstream: a string of 0s and 1s.

Format strings can be stored inside a library file. A library file has the name of the program (format-bytes) and extension .library. Library files can be placed in the same directory as the program, and/or the current directory.
A library file is a text file. Each format string has a name and takes one line: name=formatstring.

Example:
eqn=<HIHIIIIIBBBBBBBBBB40sIIBB*:XXXXXXXXXXXXXXXXXXsXXXX

This defines format string eqn. It can be retrieved with option -f name=eqn.
This format string can be followed by annotations (use a space character to separate the format string and the annotations):

Example:
eqn=<HIHIIIIIBBBBBBBBBB40sIIBB*:XXXXXXXXXXXXXXXXXXsXXXX 1: size of EQNOLEFILEHDR 9: Start MTEF header 14: Full size record 15: Line record 16: Font record 19: Shellcode (fontname)

A line in a library file that starts with # is a comment and is ignored.

FYI, Python struct module format characters are:

Character Byte order
--------------------
@         native
=         native
<         little-endian
>         big-endian
!         network (= big-endian)

Format  C Type              Standard size
-----------------------------------------
x       pad byte
c       char                1
b       signed              1
B       unsigned char       1
?       _Bool               1
h       short               2
H       unsigned short      2
i       int                 4
I       unsigned int        4
l       long                4
L       unsigned long       4
q       long long           8
Q       unsigned long long  8
f       float               4
d       double              8
s       char[]
p       char[]
P       void *

To parse a repeating sequence of bytes, use options --count (to specify the number of repetitions) and --step (to specify the number bytes between repeats).
Example:

format-bytes.py -C 2 -S 4 random.bin
File: random.bin
s:signed u:unsigned l:little-endian b:big-endian m:mixed-endian
00 1I: s -69 u 187
00 2I: sl 26043 ul 26043 sb -17563 ub 47973
00 4I: sl 881419707 ul 881419707 sb -1150973644 ub 3143993652
00 4F: l 0.000000 b -0.003502
00 4N: b 187.101.137.52 l 52.137.101.187
00 4E: l 1997/12/06 14:48:27 b 2069/08/17 19:34:12
00 8I: sl -3535861847371979333 ul 14910882226337572283 sb -4943394157892145458 ub 13503349915817406158
00 8T: ul N/A ub N/A
00 8F: l -1661678170725283018588028971660576297715302893638508902075603349019820032.000000 b -0.000000
00 16G: b BB658934-6218-EECE-3AC3-179F6B7428FB m {348965BB-1862-CEEE-3AC3-179F6B7428FB}
04 1I: s 98 u 98
04 2I: sl 6242 ul 6242 sb 25112 ub 25112
04 4I: sl -823256990 ul 3471710306 sb 1645801166 ub 1645801166
04 4F: l -1997287680.000000 b 705278197607520272384.000000
04 4N: b 98.24.238.206 l 206.238.24.98
04 4E: l 2080/01/05 19:58:26 b 2022/02/25 14:59:26
04 8I: sl -6982898039867434910 ul 11463846033842116706 sb 7068662184674531231 ub 7068662184674531231
04 8T: ul N/A ub N/A
04 8F: l -0.000000 b 358946151129582029215291849393230786808315346836706673156033999581834828933214436444158528577134449241373022018959436034143150814561128186558682352782632064229834752.000000
04 16G: b 6218EECE-3AC3-179F-6B74-28FBEB2AD62A m {CEEE1862-C33A-9F17-6B74-28FBEB2AD62A}

To search for a value inside the provided file(s), use option -F. For the moment, only integers can be searched. Start the option value with #i# followed by the decimal number to search for.
Example:

format-bytes.py -F #i#6083 random.bin
File: random.bin
0x00000009 <h 0xc317
0x00000009 <H 0xc317


As stated at the beginning of this manual, this tool is very versatile when it comes to handling files. This will be explained now.

This tool reads files in binary mode. It can read files from disk, from standard input (stdin) and from "generated" files via the command line.
It can also partially read files (this is done with the cut operator).

If no file arguments are provided to this tool, it will read data from standard input (stdin). This way, this tool can be used in a piped chain of commands, like this:

oledump.py -s 4 -d sample.doc.vir | tool.py

This tool can process JSON output from other tools using option --jsoninput:

oledump.py --json sample.doc.vir | tool.py --jsoninput

When one or more file arguments are provided to this tool, it will read the files and process the content.
How the files are read, depends on the type of file arguments that are provided. File arguments that start with character @ or # have special meaning, and will be explained later.

If a file argument does not start with @ or #, it is considered to be a file on disk and the content will be read from disk.
If the file is not a compressed file, the binary content of the file is read from disk for processing.
Compressed files are solely recognized based on their extension: .zip and .gz.
If a file argument with extension .gz is provided, the tool will decompress the gzip file in memory and process the decompressed content. No checks are made to ensure that the file with extension .gz is an actual gzip compressed file.
If a file argument with extension .zip is provided, the tool will extract the first file (or only file) from the ZIP file in memory and process the decompressed content. No checks are made to ensure that the file with extension .zip is an actual ZIP compressed file.
Password protected ZIP files can be processed too. The tool uses password 'infected' (without quotes) as default password. A different password can be provided using option --password.

Example:

tool.py sample.zip

To prevent the tool from decompressing .zip or .gz files, but to process the compressed file itself, use option --noextraction.

File arguments that start with character @ ("here files"), are read as text files that contain file arguments (one per line) to be processed.
For example, we take a text file with filename list.txt and following content:

sample-1.bin
sample-5.bin
sample-7.bin

When using this file (list.txt) in the following command:

tool.py @list.txt

the tool will process the following files: sample-1.bin, sample-5.bin and sample-7.bin.
A single @ character as filename is a here file read from stdin.

Wildcards are supported too. The classic *, ? and [] wildcard characters are supported. For example, use the following command to process all .exe and .dll files in the Windows directory:

tool.py C:\Windows\*.exe C:\Windows\*.dll

To prevent the tool from processing file arguments with wildcard characters or special initial characters (@ and #) differently, but to process them as normal files, use option --literalfilenames.

File arguments that start with character # have special meaning. These are not processed as actual files on disk (except when option --literalfilenames is used), but as file arguments that specify how to "generate" the file content.

File arguments that start with #, #h#, #b# or #e# are used to "generate" the file content.
Arguments that start with #c# are not file arguments, but cut operators (explained later).

Generating the file content with a # file argument means that the file content is not read from disk, but generated in memory based on the characteristics provided via the file argument.

When a file argument starts with # (and not with #h#, #b#, #e# or #c#), all characters that follow the # character specify the content of the generated file.
For example, file argument #ABCDE specifies a file containing exactly 5 bytes: ASCII characters A, B, C, D and E.
Thus the following command:

tool.py #ABCDE

will make the tool process data with binary content ABCDE. #ABCDE is not an actual file written on disk, but it is a notational convention to provide data via the command line.

Since this notation can not be used to specify all possible byte values, hexadecimal encoding (#h#) and BASE64 encoding (#b#) notation is supported too.
For example, #h#4142434445 is an hexadecimal notation that generates data ABCDE. Hexadecimal notation allows the generation of non-printable characters for example, like NULL bytes: #h#00
File argument #b#QUJDREU= is another example, this time BASE64 notation, that generates data ABCDE.

File arguments that start with #e# are a notational convention to use expressions to generate data. An expression is a single function/string or the concatenation of several functions/strings (using character + as concatenation operator).
Strings can be characters enclosed by single quotes ('example') or hexadecimal strings prefixed by 0x (0xBEEF).
4 functions are available: random, loremipsum, repeat and chr.

Function random takes exactly one argument: an integer (with value 1 or more). Integers can be specified using decimal notation or hexadecimal notation (prefix 0x).
The random function generates a sequence of bytes with a random value (between 0 and 255), the argument specifies how many bytes need to be generated. Remark that the random number generator that is used is just the Python random number generator, not a cryptographic random number generator.

Example:

tool.py #e#random(100)

will make the tool process data consisting of a sequence of 100 random bytes.

Function loremipsum takes exactly one argument: an integer (with value 1 or more).
The loremipsum function generates "lorem ipsum" text (fake latin), the argument specifies the number of sentences to generate.

Example: #e#loremipsum(2) generates this text:
Ipsum commodo proin pulvinar hac vel nunc dignissim neque eget odio erat magna lorem urna cursus fusce facilisis porttitor congue eleifend taciti. Turpis duis suscipit facilisi tristique dictum praesent natoque sem mi egestas venenatis per dui sit sodales est condimentum habitasse ipsum phasellus non bibendum hendrerit.

Function chr takes one argument or two arguments.
chr with one argument takes an integer between 0 and 255, and generates a single byte with the value specified by the integer.
chr with two arguments takes two integers between 0 and 255, and generates a byte sequence with the values specified by the integers.
For example #e#chr(0x41,0x45) generates data ABCDE.

Function repeat takes two arguments: an integer (with value 1 or more) and a byte sequence. This byte sequence can be a quoted string of characters (single quotes), like 'ABCDE' or an hexadecimal string prefixed with 0x, like 0x4142434445.
The repeat function will create a sequence of bytes consisting of the provided byte sequence (the second argument) repeated as many times as specified by the first argument.
For example, #e#repeat(3, 'AB') generates byte sequence ABABAB.

When more than one function needs to be used, the byte sequences generated by the functions can be concatenated with the + operator.
For example, #e#repeat(10,0xFF)+random(100) will generate a byte sequence of 10 FF bytes followed by 100 random bytes.

File arguments that start with #p# are a notational convention to pack a Python expression to generate data (using Python module struct).
The string after #p# must contain 2 expressions separated by a # character, like #p#I#123456.
The first expression (I in this example) is the format string for the Python struct.pack function, and the second expression (123456 in this example) is a Python expression that needs to be packed by struct.pack.
In this example, format string I represents an unsigned, 32-bit, little-endian integer, and thus #p#I#123456 generates byte sequence 40E20100 (hexadecimal).

The cut argument (or cut operator) allows for the partial selection of the content of a file. This argument starts with #c# followed by a "cut-expression". Use this expression to "cut out" part of the content.
The cut-argument must be put in front of a file argument, like in this example:

tool.py #c#0:100l data.bin

With these arguments, tool.py will only process the first 100 bytes (0:100l) of file data.bin.

A cut argument is applied to all file arguments that follow it. Example:

tool.py #c#0:100l data-1.bin data-2.bin

With these arguments, tool.py will only process the first 100 bytes (0:100l) of file data-1.bin and the first 100 bytes file data-2.bin.

More than one cut argument can be used, like in this example:

tool.py #c#0:100l data-1.bin #c#0:200l data-2.bin

With these arguments, tool.py will only process the first 100 bytes (0:100l) of file data-1.bin and the first 200 bytes (0:200l) of file data-2.bin.

This cut-expression is composed of 2 terms separated by a colon (:), like this:
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
This cut-expression can be used to dump the first 256 bytes of a PE file located inside the stream: ['MZ']:0x100l
This cut-expression can be used to dump the OLE file located inside the stream: [d0cf11e0]:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

LIBRARY_EXTENSION = '.library'

KEYWORD_FORMAT = 'format'
KEYWORD_TLV = 'tlv'
KEYWORD_TYPE = 'type'
KEYWORD_LENGTH = 'length'
KEYWORD_SUFFIX = 'suffix'
KEYWORD_BITSTREAM = 'bitstream'
KEYWORD_BITS = 'bits'
KEYWORD_JOIN = 'join'

dLibrary = {}

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

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

def RINSub(data, specialcharacters=''):
    if specialcharacters != '':
        for specialcharacter in specialcharacters:
            if specialcharacter in data:
                return repr(data)
        return data
    elif "'" + data + "'" == repr(data):
        return data
    else:
        return repr(data)

# RIN: Repr If Needed
def RIN(data, specialcharacters=''):
    if type(data) == list:
        return [RINSub(item, specialcharacters) for item in data]
    else:
        return RINSub(data, specialcharacters)

#----------------------------------------------------------------------------------------------------
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
                decoded += ''.join([chr(n) for n in range(number, number2 + 1)])
        else:
            print('Error: unknown function: %s' % functionname)
            return None
    return decoded

def ParsePackExpression(data):
    try:
        packFormat, pythonExpression = data.split('#', 1)
        data = struct.pack(packFormat, int(pythonExpression))
        return data
    except:
        return None

FCH_FILENAME = 0
FCH_DATA = 1
FCH_ERROR = 2

def FilenameCheckHash(filename, literalfilename):
    if literalfilename:
        return FCH_FILENAME, filename
    elif filename.startswith('#h#'):
        result = Hex2Bytes(filename[3:].replace(' ', ''))
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
            return FCH_DATA, C2BIP3(result)
    elif filename.startswith('#p#'):
        result = ParsePackExpression(filename[3:])
        if result == None:
            return FCH_ERROR, 'pack'
        else:
            return FCH_DATA, result
    elif filename.startswith('#'):
        return FCH_DATA, C2BIP3(filename[1:])
    else:
        return FCH_FILENAME, filename

class cBinaryFile:
    def __init__(self, filename, zippassword='infected', noextraction=False, literalfilename=False, content=None):
        self.filename = filename
        self.zippassword = zippassword
        self.noextraction = noextraction
        self.literalfilename = literalfilename
        self.oZipfile = None
        self.extracted = False

        if content != None:
            self.fIn = DataIO(content)
            return

        fch, data = FilenameCheckHash(self.filename, self.literalfilename)
        if fch == FCH_ERROR:
            raise Exception('Error %s parsing filename: %s' % (data, self.filename))

        if self.filename == '':
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            self.fIn = sys.stdin
        elif fch == FCH_DATA:
            self.fIn = DataIO(data)
        elif not self.noextraction and self.filename.lower().endswith('.zip'):
            self.oZipfile = zipfile.ZipFile(self.filename, 'r')
            if len(self.oZipfile.infolist()) == 1:
                self.fIn = self.oZipfile.open(self.oZipfile.infolist()[0], 'r', self.zippassword)
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

    def close(self):
        if self.fIn != sys.stdin:
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
        data = self.fIn.read()
        self.close()
        return data

#----------------------------------------------------------------------------------------------------

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
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

def Glob(filename):
    filenames = glob.glob(filename)
    if len(filenames) == 0:
        return [filename]
    else:
        return filenames

def ExpandFilenameArguments(filenames, literalfilenames=False):
    if len(filenames) == 0:
        return [['', '']]
    elif literalfilenames:
        return [[filename, ''] for filename in filenames]
    else:
        cutexpression = ''
        result = []
        for filename in list(collections.OrderedDict.fromkeys(sum(map(Glob, sum(map(ProcessAt, filenames), [])), []))):
            if filename.startswith('#c#'):
                cutexpression = filename[3:]
            else:
                result.append([filename, cutexpression])
        if result == []:
            return [['', cutexpression]]
        return result

def CheckJSON(stringJSON):
    try:
        object = json.loads(stringJSON)
    except:
        print('Error parsing JSON')
        print(sys.exc_info()[1])
        return None
    if not isinstance(object, dict):
        print('Error JSON is not a dictionary')
        return None
    if not 'version' in object:
        print('Error JSON dictionary has no version')
        return None
    if object['version'] != 2:
        print('Error JSON dictionary has wrong version')
        return None
    if not 'id' in object:
        print('Error JSON dictionary has no id')
        return None
    if object['id'] != 'didierstevens.com':
        print('Error JSON dictionary has wrong id')
        return None
    if not 'type' in object:
        print('Error JSON dictionary has no type')
        return None
    if object['type'] != 'content':
        print('Error JSON dictionary has wrong type')
        return None
    if not 'fields' in object:
        print('Error JSON dictionary has no fields')
        return None
    if not 'name' in object['fields']:
        print('Error JSON dictionary has no name field')
        return None
    if not 'content' in object['fields']:
        print('Error JSON dictionary has no content field')
        return None
    if not 'items' in object:
        print('Error JSON dictionary has no items')
        return None
    for item in object['items']:
        item['content'] = binascii.a2b_base64(item['content'])
    return object['items']

def GenerateFileList(args, options):
    if len(args) > 0 and options.jsoninput:
        print('Error: option -j can not be used with files')
        return None

    result = []
    if options.jsoninput:
        items = CheckJSON(sys.stdin.read())
        if items == None:
            return None
        for item in items:
            result.append((item['name'], '', item['content']))
    else:
        for filename, cutexpression in ExpandFilenameArguments(args, options.literalfilenames):
            result.append((filename, cutexpression, None))
    return result

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
        oMatch = re.match(r"\[\'(.+?)\'\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
        else:
            return CUTTERM_FIND, (binascii.a2b_hex(oMatch.group(1)), int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]
    if oMatch == None:
        return None, None, argument
    else:
        return CUTTERM_FIND, (oMatch.group(1), int(Replace(oMatch.group(2), {None: '1'})), ParseInteger(Replace(oMatch.group(3), {None: '0'}))), argument[len(oMatch.group(0)):]

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

def Timestamp2StringLog(stime):
    return '%04d%02d%02d-%02d%02d%02d' % stime[0:6]

def Timestamp2StringHuman(stime):
    return '%04d/%02d/%02d %02d:%02d:%02d' % stime[0:6]

def TimestampLocal(epoch=None):
    if epoch == None:
        return Timestamp2StringHuman(time.localtime())
    else:
        return Timestamp2StringHuman(time.localtime(epoch))

def TimestampUTC(epoch=None):
    if epoch == None:
        return Timestamp2StringHuman(time.gmtime())
    else:
        return Timestamp2StringHuman(time.gmtime(epoch))

def FiletimeUTC(value):
    try:
        return '%s.%07d' % (datetime.datetime.utcfromtimestamp((value - 116444736000000000) / 10000000).strftime("%Y/%m/%d %H:%M:%S"), (value - 116444736000000000) % 10000000)
    except (ValueError, OSError):
        return 'N/A'

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

def OIDDERDecode(bytes):
    byte = bytes[0]
    if byte < 40:
        result = [0, byte]
    elif byte < 80:
        result = [1, byte - 40]
    else:
        result = [2, byte - 80]

    result2 = []
    for byte in bytes[1:] + [-1]:
        if result2 == []:
            if byte < 128:
                result.append(byte)
            elif byte == 128:
                return None
            else:
                result2.append(byte)
        else:
            if byte == -1:
                return None
            result2.append(byte)
            if byte < 128:
                bits = 0
                for number in result2:
                    bits = bits << 7 | number & 0x7F
                result.append(bits)
                result2 = []
    if result2 != [] or result[-1] != -1:
        None
    
    return '.'.join(map(str, result[:-1]))

def FormatBytesData(data, position, options):
    if len(data) == 0:
        return
    bytes = [C2IIP2(d) for d in data]

    if position < 0:
        prefix = ''
    else:
        prefix = '%02X ' % position

    if len(data) >= 3 and bytes[0] == 6 and bytes[1] > 0 and bytes[1] <= 32 and bytes[1] <= len(data) - 2:
        oid = OIDDERDecode(bytes[2:2 + bytes[1]])
        if oid != None:
            print(prefix + 'OID: %s' % oid)

    print(prefix + '1I: s %d u %d' % (struct.unpack('b', data[0:1])[0], struct.unpack('B', data[0:1])[0]))

    if len(data) < 2:
        return
    print(prefix + '2I: sl %d ul %d sb %d ub %d' % (struct.unpack('<h', data[0:2])[0], struct.unpack('<H', data[0:2])[0], struct.unpack('>h', data[0:2])[0], struct.unpack('>H', data[0:2])[0]))

    if len(data) < 4:
        return
    print(prefix + '4I: sl %d ul %d sb %d ub %d' % (struct.unpack('<i', data[0:4])[0], struct.unpack('<I', data[0:4])[0], struct.unpack('>i', data[0:4])[0], struct.unpack('>I', data[0:4])[0]))
    print(prefix + '4F: l %f b %f' % (struct.unpack('<f', data[0:4])[0], struct.unpack('>f', data[0:4])[0]))
    print(prefix + '4N: b %d.%d.%d.%d l %d.%d.%d.%d' % (bytes[0], bytes[1], bytes[2], bytes[3], bytes[3], bytes[2], bytes[1], bytes[0]))
    print(prefix + '4E: l %s b %s' % (TimestampUTC(struct.unpack('<I', data[0:4])[0]), TimestampUTC(struct.unpack('>I', data[0:4])[0])))

    if len(data) < 8:
        return
    print(prefix + '8I: sl %d ul %d sb %d ub %d' % (struct.unpack('<q', data[0:8])[0], struct.unpack('<Q', data[0:8])[0], struct.unpack('>q', data[0:8])[0], struct.unpack('>Q', data[0:8])[0]))
    print(prefix + '8T: ul %s ub %s' % (FiletimeUTC(struct.unpack('<Q', data[0:8])[0]), FiletimeUTC(struct.unpack('>Q', data[0:8])[0])))
    print(prefix + '8F: l %f b %f' % (struct.unpack('<d', data[0:8])[0], struct.unpack('>d', data[0:8])[0]))

    if len(data) < 16:
        return
    print(prefix + '16G: b %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X m {%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}' % tuple(bytes[0:16] + bytes[3::-1] + bytes[5:3:-1] + bytes[7:5:-1] + bytes[8:16]))

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
    return binascii.hexlify(data[:16])

def ExtraInfoHEADASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(c) >= 32 and P23Ord(c) < 127, chr(P23Ord(c)), '.') for c in data[:16]])

def ExtraInfoTAILHEX(data):
    if data == None:
        return ''
    return binascii.hexlify(data[-16:])

def ExtraInfoTAILASCII(data):
    if data == None:
        return ''
    return ''.join([IFF(P23Ord(c) >= 32 and P23Ord(c) < 127, chr(P23Ord(c)), '.') for c in data[-16:]])

def ExtraInfoHISTOGRAM(data):
    if data == None:
        return ''
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
    if data == None:
        return ''
    dPrevalence = {iter: 0 for iter in range(0x100)}
    for char in data:
        dPrevalence[ord(char)] += 1
    sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes = CalculateByteStatistics(dPrevalence)
    return '%d,%d,%d,%d,%d' % (countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes)

def GenerateExtraInfo(extra, data):
    if extra == '':
        return ''
    if extra.startswith('!') or extra.startswith('#'):
        extra = extra[1:]
    dExtras = {'%LENGTH%': lambda x: IFF(data == None, '', lambda: '%d' % len(data)),
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
            extra = extra.replace(variable, dExtras[variable](data))
    return extra.replace(r'\t', '\t').replace(r'\n', '\n')

#-BEGINCODE cDump------------------------------------------------------------------------------------
#import binascii
#import sys
#if sys.version_info[0] >= 3:
#    from io import StringIO
#else:
#    from cStringIO import StringIO

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
            return ord(data)
#-ENDCODE cDump--------------------------------------------------------------------------------------

def HexDump(data):
    return cDump(data).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data).HexAsciiDump(rle=rle)

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        if isinstance(data, str):
            data = bytes(data, 'utf-8', 'backslashreplace')
        sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

def SearchAndReplaceFormatCallBack(oMatch):
    return '%ds' % int(oMatch.groups()[0], 16)

def SearchAndReplaceFormat(format):
    return re.sub(r'0x([0-9a-fA-F]+)s', SearchAndReplaceFormatCallBack, format)

def MergeUserLibrarySub(filename):
    global dLibrary

    lines = File2Strings(filename)
    if not lines:
        return
    for line in lines:
        if not line.startswith('#'):
            result = line.split('=', 1)
            if len(result) == 2:
                values = result[1].split(' ', 1)
                if len(values) == 2:
                    dLibrary[result[0]] = values
                else:
                    dLibrary[result[0]] = [result[1], '']

def NumberToHex(number):
    result = hex(number)
    if len(result) % 2 == 1:
        result = '0x0' + result[2:]
    return result

def MergeUserLibrary():
    MergeUserLibrarySub(os.path.splitext(sys.argv[0])[0] + LIBRARY_EXTENSION)
    MergeUserLibrarySub(os.path.splitext(os.path.basename(sys.argv[0]))[0] + LIBRARY_EXTENSION)

def PrintLibrary():
    global dLibrary

    print('Valid format library names:')
    for key in sorted(dLibrary.keys()):
        print(' %s: %s %s' % (key, dLibrary[key][0], dLibrary[key][1]))

def Library(name):
    global dLibrary

    MergeUserLibrary()

    try:
        return dLibrary[name]
    except KeyError:
        print('Invalid format library name: %s' % name)
        print('')
        PrintLibrary()
        sys.exit(-1)

def ParseFormat(formatvalue):
    annotations = ''
    representation = ''
    remainder = False
    special = None
    if formatvalue.startswith('name='):
        formatvalue, annotations = Library(formatvalue[5:])
    if formatvalue.startswith(KEYWORD_TLV + '='):
        special = {KEYWORD_FORMAT: KEYWORD_TLV}
        for element in formatvalue[len(KEYWORD_TLV + '='):].split(','):
            if element.startswith('f:'):
                format = element[2:]
            elif element.startswith('t:'):
                special[KEYWORD_TYPE] = int(element[2:])
            elif element.startswith('l:'):
                special[KEYWORD_LENGTH] = int(element[2:])
            elif element.startswith('s:'):
                special[KEYWORD_SUFFIX] = element[2:]
            else:
                raise
    elif formatvalue.startswith(KEYWORD_BITSTREAM + '='):
        special = {KEYWORD_FORMAT: KEYWORD_BITSTREAM}
        for element in formatvalue[len(KEYWORD_BITSTREAM + '='):].split(','):
            if element.startswith('f:'):
                format = element[2:]
            elif element.startswith('b:'):
                special[KEYWORD_BITS] = [int(number) for number in element[2:].split(';')]
            elif element.startswith('j:'):
                special[KEYWORD_JOIN] = element[2:]
            else:
                raise
    else:
        formats = formatvalue.split(':')
        if len(formats) == 2:
            format, representation = formats
        else:
            format = formats[0]
        if format.endswith('*'):
            format = format[:-1]
            remainder = True

    return SearchAndReplaceFormat(format), representation, annotations, remainder, special

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

def ParseAnnotations(annotations, dAnnotations):
    index = None
    for token in re.split(r'(\d+:)', annotations):
        if token.endswith(':'):
            index = int(token[:-1])
        elif index != None:
            dAnnotations[index] = token.strip()

def FormatBytesSingle(filename, cutexpression, content, options):
    MergeUserLibrary()

    format, representation, annotations, remainder, special = ParseFormat(options.format)

    dAnnotations = {}
    if options.annotations != '':
        ParseAnnotations(options.annotations, dAnnotations)
    elif annotations != '':
        ParseAnnotations(annotations, dAnnotations)

    oBinaryFile = cBinaryFile(filename, C2BIP3(options.password), options.noextraction, options.literalfilenames, content)
    if cutexpression == '':
        if format != '':
            if remainder or special != None:
                data = oBinaryFile.read()
            else:
                data = oBinaryFile.read(struct.calcsize(format))
        elif options.find != '':
            data = oBinaryFile.read()
        else:
            data = oBinaryFile.read(options.count * options.step + 16)
    else:
        data = CutData(oBinaryFile.read(), cutexpression)
    oBinaryFile.close()

    dumpData = options.select.DoSelect or special != None and special[KEYWORD_FORMAT] == KEYWORD_BITSTREAM

    if filename != '' and not dumpData:
        print('File: %s%s' % (filename, IFF(oBinaryFile.extracted, ' (extracted)', '')))
    if format == '' and options.find == '':
        print('s:signed u:unsigned l:little-endian b:big-endian m:mixed-endian')
    if format != '':
        if dumpData:
            if options.dump:
                DumpFunction = lambda x:x
                IfWIN32SetBinary(sys.stdout)
            elif options.hexdump:
                DumpFunction = HexDump
            elif options.asciidumprle:
                DumpFunction = lambda x: HexAsciiDump(x, True)
            else:
                DumpFunction = HexAsciiDump

        if special == None:
            size = struct.calcsize(format)
            for index, element in enumerate(struct.unpack(format, data[0:size])):
                index += 1
                if options.select.DoSelect:
                    if (isinstance(element, str) or isinstance(element, bytes)) and options.select.Select(index):
                        StdoutWriteChunked(DumpFunction(element))
                else:
                    if isinstance(element, int) or sys.version_info[0] == 2 and isinstance(element, long):
                        if representation == '':
                            line = '%2d: %15s %10d %10x  %s' % (index, type(element), element, element, IFF(element < 0, '', lambda: TimestampUTC(element)))
                        elif representation[index - 1] == 'X':
                            line = '%2d: %15s %10x' % (index, type(element), element)
                        elif representation[index - 1] == 'I':
                            line = '%2d: %15s %10d' % (index, type(element), element)
                        elif representation[index - 1] == 'E':
                            line = '%2d: %15s %s' % (index, type(element), IFF(element < 0, '', lambda: TimestampUTC(element)))
                        elif representation[index - 1] == 'T':
                            line = '%2d: %15s %s' % (index, type(element), IFF(element < 0, '', lambda: FiletimeUTC(element)))
                    elif isinstance(element, str):
                        if representation != '' and representation[index - 1] == 'S':
                            line = '%2d: %15s %s' % (index, type(element), RIN(element))
                        elif representation != '' and representation[index - 1] == 'X':
                            line = '%2d: %15s %s' % (index, type(element), binascii.b2a_hex(element))
                        else:
                            line = '%2d: %15s %10d %s %s %s %s' % (index, type(element), len(element), ExtraInfoHEADASCII(element[:10]), ExtraInfoHEADHEX(element[:10]), ExtraInfoENTROPY(element), CalculateChosenHash(element)[0])
                    elif isinstance(element, bytes):
                        line = '%2d: %15s %10d %s %s %s %s' % (index, type(element), len(element), ExtraInfoHEADASCII(element[:10]), ExtraInfoHEADHEX(element[:10]), ExtraInfoENTROPY(element), CalculateChosenHash(element)[0])
                    else:
                        line = '%2d: %15s %s' % (index, type(element), str(element))
                    print('%s %s' % (line, dAnnotations.get(index, '')))
            if remainder and options.select.Select('r'):
                StdoutWriteChunked(DumpFunction(data[size:]))
            if not options.select.DoSelect and remainder:
                print('Remainder: %d' % (len(data) - size))
                remainderx100 = data[size:size + 0x100]
                if len(remainderx100) > 0:
                    oDump = cDump(remainderx100)
                    print(oDump.HexAsciiDump())
                    FormatBytesData(remainderx100, -1, options)
        elif special[KEYWORD_FORMAT] == KEYWORD_TLV:
            size = struct.calcsize(format)
            if KEYWORD_SUFFIX in special:
                sizeSuffix = struct.calcsize(special[KEYWORD_SUFFIX])
            else:
                sizeSuffix = 0
            index = 0
            while len(data) >= size:
                index += 1
                fields = struct.unpack(format, data[0:size])
                data = data[size:]
                value = data[:fields[special[KEYWORD_LENGTH]]]
                data = data[fields[special[KEYWORD_LENGTH]] + sizeSuffix:]
                if options.select.DoSelect:
                    if options.select.Select(index):
                        StdoutWriteChunked(DumpFunction(value))
                else:
                    line = '%2d: %8s %5d %s' % (index, NumberToHex(fields[special[KEYWORD_TYPE]]), fields[special[KEYWORD_LENGTH]], repr(value)[0:40])
                    print(line)
            if len(data) > 0 and options.select.Select('r'):
                StdoutWriteChunked(DumpFunction(data))
            if not options.select.DoSelect and len(data) > 0:
                print('Remainder: %d' % (len(data)))
                remainderx100 = data[:0x100]
                if len(remainderx100) > 0:
                    oDump = cDump(remainderx100)
                    print(oDump.HexAsciiDump())
                    FormatBytesData(remainderx100, -1, options)
        else:
            size = struct.calcsize(format)
            index = 0
            bits = ''
            oResult = DataIO()
            if special[KEYWORD_JOIN] == '<':
                joinLittleendian = True
                outputBytes = True
            elif special[KEYWORD_JOIN] == '>':
                joinLittleendian = False
                outputBytes = True
            elif special[KEYWORD_JOIN] == 'b':
                joinLittleendian = False
                outputBytes = False
            else:
                raise
            while len(data) - size * index >= size:
                fields = struct.unpack(format, data[index * size:(index + 1) * size])
                for bit in special[KEYWORD_BITS]:
                    bitPattern = 2 ** bit
                    if fields[0] & bitPattern == bitPattern:
                        bit = '1'
                    else:
                        bit = '0'
                    if joinLittleendian:
                        bits = bit + bits
                    else:
                        bits = bits + bit
                    if outputBytes and len(bits) == 8:
                        oResult.write(C2BIP3(chr(int(bits, 2))))
                        bits = ''
                index += 1
            if outputBytes and len(bits) != 0:
                padding = '0' * (8 - len(bits))
                if joinLittleendian:
                    bits = padding + bits
                else:
                    bits = bits + padding
                oResult.write(C2BIP3(chr(int(bits, 2))))
            if outputBytes:
                StdoutWriteChunked(DumpFunction(oResult.getvalue()))
            else:
                StdoutWriteChunked(bits)

        if options.select.DoSelect and options.select.selectionCounter == 0:
            print('Warning: no item was selected with expression %s' % options.select.option)
    elif options.find != '':
        if not options.find.startswith('#i#'):
            raise Exception('Unknown find option format: %s' % options.find)
        searches = []
        for c in 'bBhHiIqQ':
            for e in '<>':
                format = e + c
                try:
                    searches.append([format, struct.pack(format, int(options.find[3:]))])
                except struct.error:
                    pass
        for search in searches:
            for position in FindAll(data, search[1]):
                print('0x%08x %s 0x%s' % (position, search[0], binascii.b2a_hex(search[1])))
    elif options.count == 1:
        FormatBytesData(data, -1, options)
    else:
        position = 0
        for iter in range(options.count):
            FormatBytesData(data[position:], position, options)
            position += options.step

def FormatBytesFiles(fileList, options):
    for filename, cutexpression, content in fileList:
        FormatBytesSingle(filename, cutexpression, content, options)

class cSelection(object):
    def __init__(self, option):
        self.option = option
        self.selectionCounter = 0
        if self.option == '':
            self.selector = []
            self.DoSelect = False
        else:
            self.DoSelect = True
            if self.option == 'r':
                self.selector = ['r']
            elif '-' in self.option:
                begin, end = self.option.split('-')
                self.selector = list(range(int(begin), int(end) + 1))
            else:
                self.selector = [int(self.option)]

    def Select(self, index):
        result = index in self.selector
        if result:
            self.selectionCounter += 1
        return result

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file|cut-expression ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-f', '--format', default='', help='Struct format string to use')
    oParser.add_option('-n', '--annotations', default='', help='Annotations')
    oParser.add_option('-s', '--select', default='', help='Select item nr for dumping or r for remainder')
    oParser.add_option('-F', '--find', default='', help='Find value')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-C', '--count', type=int, default=1, help='The number of repeating bytes (default 1)')
    oParser.add_option('-S', '--step', type=int, default=1, help='The step to use when option --count is not 1 (default 1)')
    oParser.add_option('--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--jsoninput', action='store_true', default=False, help='Consume JSON from stdin')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    options.select = cSelection(options.select)
    fileList = GenerateFileList(args, options)
    if fileList != None:
        FormatBytesFiles(fileList, options)

if __name__ == '__main__':
    Main()
