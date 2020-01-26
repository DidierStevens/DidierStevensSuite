#!/usr/bin/env python

__description__ = 'This is essentialy a wrapper for the hashlib module'
__author__ = 'Didier Stevens'
__version__ = '0.0.8'
__date__ = '2020/01/25'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/11/29: start
  2017/12/01: started man
  2017/12/02: finished man
  2018/02/09: added option --recursedir
  2018/03/05: 0.0.3 updated #e# expressions
  2018/04/16: added option -s
  2018/06/12: 0.0.4 cosmetic change
  2018/06/17: 0.0.5 added option -v
  2018/09/18: 0.0.6 added option -C
  2019/08/27: 0.0.7 added crc32
  2020/01/25: 0.0.8 added checksum8; added ParsePackExpression #p#; added #h# support for spaces; bugfix #e#chr

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
import hashlib
import fnmatch
import zlib
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO

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

def PrintManual():
    manual = r'''
Manual:

This tool is essentialy a wrapper for the Python hashlib module.

It reads one or more files or stdin and calculates hash values for each file. This tool is very versatile when it comes to handling files, later full details will be provided.

This Python script was developed with Python 2.7 and tested with Python 2.7 and 3.5.

By default, this tool reads each file and calculates the hash values for each complete file. The hash algorithms used by default are md5, sha1 and sha256.

Example:

hash.py C:\Windows\notepad.exe
md5   : fc2ea5bd5307d2cfa5aaa38e0c0ddce9
sha1  : a3b46609d159615d5c78f5c54ea24d46805ce374
sha256: 0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1

One can provide several files to process:

hash.py C:\Windows\notepad.exe C:\Windows\write.exe
File: c:\Windows\notepad.exe
 md5   : fc2ea5bd5307d2cfa5aaa38e0c0ddce9
 sha1  : a3b46609d159615d5c78f5c54ea24d46805ce374
 sha256: 0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1
File: c:\Windows\write.exe
 md5   : 73e19be0e0ecd88616b5762f621b0226
 sha1  : 27cdeb38a55826936d5b55f54984447398c5d996
 sha256: e559c2673d312a0089d8dcdfaecd7fe261f74aaaf02a110722b34a0c85574012

In such a case, the filename will be printed too.

To display just the hash value, and suppress all other output, use option -q (quiet):

hash.py -q C:\Windows\notepad.exe C:\Windows\write.exe
fc2ea5bd5307d2cfa5aaa38e0c0ddce9
a3b46609d159615d5c78f5c54ea24d46805ce374
0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1
73e19be0e0ecd88616b5762f621b0226
27cdeb38a55826936d5b55f54984447398c5d996
e559c2673d312a0089d8dcdfaecd7fe261f74aaaf02a110722b34a0c85574012

Option -q is ignored when option -b is used (options -b, block mode, will be explained later).
This option is more useful when you select the hash algorithm with option -a, like this:

hash.py -a md5 -q C:\Windows\notepad.exe C:\Windows\write.exe
fc2ea5bd5307d2cfa5aaa38e0c0ddce9
73e19be0e0ecd88616b5762f621b0226

This produces a list of md5 hashes.

Option -a can take a list of hash algorithms, separated by character ; or ,. Like this:

hash.py -a md5;sha256 C:\Windows\notepad.exe C:\Windows\write.exe
File: c:\Windows\notepad.exe
 md5   : fc2ea5bd5307d2cfa5aaa38e0c0ddce9
 sha256: 0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1
File: c:\Windows\write.exe
 md5   : 73e19be0e0ecd88616b5762f621b0226
 sha256: e559c2673d312a0089d8dcdfaecd7fe261f74aaaf02a110722b34a0c85574012

If you always want to use the same set of hash algorithms, you can set environment variable HASH_ALGORITHMS with the list of your preferred hash algorithms and export it.

The list of hash algorithms supported by the Python version this script is running on, is:
''' + ' '.join(name for name in list(hashlib.algorithms_available) + list(dSpecialHashes.keys())) + r'''

Hash checksum8 is the sum of all bytes inside the file, interpreted as unsigned, 8-bit integers.

The Python hashlib module methods produce hexadecimal hash values with lowercase letters. To get uppercase letters with this tool, use option -u:

hash.py -u C:\Windows\notepad.exe
md5   : FC2EA5BD5307D2CFA5AAA38E0C0DDCE9
sha1  : A3B46609D159615D5C78F5C54EA24D46805CE374
sha256: 0F8A84968FAC3CADC04471C1EE5C4644414491C89A4A7149845C170258B6A6D1

To produce a csv list, use option -C:

hash.py -C -a md5 C:\Windows\notepad.exe C:\Windows\write.exe
C:\Windows\notepad.exe;9512e1cc66a1d36feb0a290cab09087b
C:\Windows\write.exe;5266c61652051e9ef3a4d199001f6b17

This tool can also be used to globally compare files. With option -c, the hash value(s) of each file will be compared and a report will be produced, like this:

hash.py -c C:\Windows\notepad.exe C:\Windows\write.exe
File: c:\Windows\notepad.exe
 md5   : fc2ea5bd5307d2cfa5aaa38e0c0ddce9
 sha1  : a3b46609d159615d5c78f5c54ea24d46805ce374
 sha256: 0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1
File: c:\Windows\write.exe
 md5   : 73e19be0e0ecd88616b5762f621b0226
 sha1  : 27cdeb38a55826936d5b55f54984447398c5d996
 sha256: e559c2673d312a0089d8dcdfaecd7fe261f74aaaf02a110722b34a0c85574012

File hash summary:
 All files have different md5 hashes
 There are 2 different md5 hashes
 All files have different sha1 hashes
 There are 2 different sha1 hashes
 All files have different sha256 hashes
 There are 2 different sha256 hashes

As this command can produce a long report, it can be useful to combine option -c with options -q and -a to restrict comparison to one hash algorithm, like this:

hash.py -c -a sha256 -q C:\Windows\notepad.exe C:\Windows\write.exe
0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1
e559c2673d312a0089d8dcdfaecd7fe261f74aaaf02a110722b34a0c85574012

File hash summary:
 All files have different sha256 hashes
 There are 2 different sha256 hashes

To illustrate a report when identical files are compared (based on the hash value), this example uses a copy of the file notepad.exe:

hash.py -c -a sha256 -q C:\Windows\notepad.exe C:\Windows\write.exe notepad_copy.exe
e9f2fbe8e1bc49d107df36ef09f6d0aeb8901516980d3fe08ee73ab7b4a2325f
97cea2bf66a715bd470f4c94adbb3a4caf8b740763651a91cf8c9bc0528d4e62
e9f2fbe8e1bc49d107df36ef09f6d0aeb8901516980d3fe08ee73ab7b4a2325f

File hash summary:
 Files (2) with identical sha256 hash value e9f2fbe8e1bc49d107df36ef09f6d0aeb8901516980d3fe08ee73ab7b4a2325f:
  C:\Windows\notepad.exe
  notepad_copy.exe
 Files with unique sha256 hash value:
  C:\Windows\write.exe
 There are 2 different sha256 hashes

Option -s can take a list of hashes to skip, separated by character ; or ,. This option is useful in combination with option -c, to skip specified hash values when comparing.
Option -v can take a list of hashes to validate, separated by character ; or ,.

Example:

hash.py -v fc2ea5bd5307d2cfa5aaa38e0c0ddce9 C:\Windows\notepad.exe
md5   : fc2ea5bd5307d2cfa5aaa38e0c0ddce9 (validated)
sha1  : a3b46609d159615d5c78f5c54ea24d46805ce374
sha256: 0f8a84968fac3cadc04471c1ee5c4644414491c89a4a7149845c170258b6a6d1

This tool can also split each processed file in blocks and calculate hash values for each block. This "block mode" is initiated with option -b.
Option -c (compare) and option -b (block) are mutually exclusive.

Option -b requires an integer: the size of the block. This can be a decimal integer (example 1000) or an hexadecimal integer (example 0xA00).

Here is an example with block size hundred thousand (100000) and one file:

hash.py -b 100000 C:\Windows\notepad.exe
md5   : 100000 c410e2707bf048beb78194dc17f964a5
sha1  : 100000 2feffa3af0756502f6d27b7a68e71a4098795383
sha256: 100000 47c1b0067fd65629331b99fe038ee44e8d79de8c578aa666ab6ba5ee5e782cf7
md5   : 100000 4cac1269e1b7efedd234e3ee9ed9c96d
sha1  : 100000 3759f57f6007edafe55f5dd1871e6d714a5e1c8c
sha256: 100000 8a33ea00c2d010282865328ad93cc9f10a4e8af140428817ce2e1f9b446ad53a
md5   :  21184 111d464c2b0572a9cf2375be9b000dd7
sha1  :  21184 3184a846cd8a81174fc2e8c3ee99bf4a2ce92f7d
sha256:  21184 c2dda3b3dfb0974d14d22065091d7533b82fe9f205a4b6caa85cd961300d69ed
Summary md5 values: all 3 blocks are different
Summary sha1 values: all 3 blocks are different
Summary sha256 values: all 3 blocks are different

For each block, the size and hash value is displayed, followed by a summary.
In this example, all blocks are different.

When all blocks are the same (identical hash values), the output is like this (the file sample-15.bin contains only 15 bytes, each byte is the ASCII character A):

hash.py -b 5 sample-15.bin
Summary md5 values: all blocks are identical (3 blocks in total)
 f6a6263167c92de8644ac998b3c4e4d1
Summary sha1 values: all blocks are identical (3 blocks in total)
 c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403
Summary sha256 values: all blocks are identical (3 blocks in total)
 11770b3ea657fe68cba19675143e4715c8de9d763d3c21a85af6b7513d43997d

When some blocks are the same (identical hash values), the output is like this (the file sample-12.bin contains only 12 bytes, each byte is the ASCII character A):

hash.py -b 5 sample-12.bin

md5   :      5 f6a6263167c92de8644ac998b3c4e4d1
sha1  :      5 c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403
sha256:      5 11770b3ea657fe68cba19675143e4715c8de9d763d3c21a85af6b7513d43997d
md5   :      5 f6a6263167c92de8644ac998b3c4e4d1
sha1  :      5 c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403
sha256:      5 11770b3ea657fe68cba19675143e4715c8de9d763d3c21a85af6b7513d43997d
md5   :      2 3b98e2dffc6cb06a89dcb0d5c60a0206
sha1  :      2 801c34269f74ed383fc97de33604b8a905adb635
sha256:      2 58bb119c35513a451d24dc20ef0e9031ec85b35bfc919d263e7e5d9868909cb5
Summary md5 values: 2 different blocks (3 blocks in total)
Summary sha1 values: 2 different blocks (3 blocks in total)
Summary sha256 values: 2 different blocks (3 blocks in total)

Block mode is useful to identify repeating byte sequences inside files, but often requires the selection of a part of the input file. This can be done with the cut operator, that will be explained later.


As stated at the beginning of this manual, this tool is very versatile when it comes to handling files. This will be explained now.

This tool reads files in binary mode. It can read files from disk, from standard input (stdin) and from "generated" files via the command line.
It can also partially read files (this is done with the cut operator).

If no file arguments are provided to this tool, it will read data from standard input (stdin). This way, this tool can be used in a piped chain of commands, like this:

oledump.py -s 4 -d sample.doc.vir | tool.py

When one or more file arguments are provided to this tool, it will read the files and process the content.
How the files are read, depends on the type of file arguments that are provided. File arguments that start with character @ or # have special meaning, and will be explained later.

If a file argument does not start with @ or #, it is considered to be a file on disk and the content will be read from disk.
If the file is not a compressed file, the binary content of the file is read from disk for processing.
Compressed files are solely recognized based on their extension: .zip and .gz.
If a file argument with extension .gz is provided, the tool will decompress the gzip file in memory and process the decompressed content. No checks are made to ensure that the file with extension .gz is an actual gzip compressed file.
If a file argument with extension .zip is provided and it contains a single file, the tool will extract the file from the ZIP file in memory and process the decompressed content. No checks are made to ensure that the file with extension .zip is an actual ZIP compressed file.
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

This will process all .exe and .dll files inside the directory C:\Windows, but it will not process files inside subdirectories of directory C:\Windows. To process files inside subdirectories too, use option --recursedir (recurse directories).

To prevent the tool from processing file arguments with wildcard characters or special initial characters (@ and #) differently, but to process them as normal files, use option --literalfilenames. This option can not be used together with option --recursedir.

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

A cut-expression is composed of 2 terms separated by a colon (:), like this:
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

SEPARATOR = ';'
QUOTE = '"'

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
                if number < number2:
                    decoded += ''.join([chr(n) for n in range(number, number2 + 1)])
                else:
                    decoded += ''.join([chr(n) for n in range(number, number2 - 1, -1)])
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
            return FCH_DATA, result
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
    def __init__(self, filename, zippassword='infected', noextraction=False, literalfilename=False):
        self.filename = filename
        self.zippassword = zippassword
        self.noextraction = noextraction
        self.literalfilename = literalfilename
        self.oZipfile = None
        self.extracted = False

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

def ExpandFilenameArguments(filenames, literalfilenames=False, recursedir=False):
    if len(filenames) == 0:
        return [['', '']]
    elif literalfilenames:
        return [[filename, ''] for filename in filenames]
    else:
        cutexpression = ''
        result = []
        if recursedir:
            for dirwildcard in filenames:
                if dirwildcard.startswith('#c#'):
                    cutexpression = dirwildcard[3:]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            result.append([filename, cutexpression])
                    elif os.path.isfile(dirwildcard):
                        result.append([dirwildcard, cutexpression])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = '*'
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == '':
                                dirname = '.'
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                result.append([os.path.join(path, filename), cutexpression])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(Glob, sum(map(ProcessAt, filenames), [])), []))):
                if filename.startswith('#c#'):
                    cutexpression = filename[3:]
                else:
                    result.append([filename, cutexpression])
        if result == [] and cutexpression != '':
            return [['', cutexpression]]
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
        oMatch = re.match(r"\[u?\'(.+?)\'\](\d+)?([+-](?:0x[0-9a-f]+|\d+))?", argument)
    else:
        if len(oMatch.group(1)) % 2 == 1:
            raise Exception("Uneven length hexadecimal string")
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
        positionEnd = Find(stream, valueRight[0], valueRight[1], positionBegin)
        if positionEnd == -1:
            return ['', None, None]
        else:
            positionEnd += len(valueRight[0])
        positionEnd += valueRight[2]
    else:
        raise Exception("Unknown value typeRight")

    return [stream[positionBegin:positionEnd], positionBegin, positionEnd]

def GetHashObjects(algorithms):
    global dSpecialHashes
    
    dHashes = {}

    if algorithms == '':
        algorithms = os.getenv('HASH_ALGORITHMS', 'md5;sha1;sha256')
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

def ParseHashList(data):
    separator = ','
    if not separator in data:
        separator = ';'
    return data.lower().split(separator)

def ToString(value):
    if isinstance(value, str):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if len(value) > 1 and value[0] == quote and value[-1] == quote:
        return value
    if separator in value or value == '':
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

def HashSingle(filename, cutexpression, prefix, dFileHashes, options):
    oBinaryFile = cBinaryFile(filename, C2BIP3(options.password), options.noextraction, options.literalfilenames)
    data = oBinaryFile.read()
    if cutexpression != '':
        data = CutData(data, cutexpression)[0]
    hashes, dHashes = GetHashObjects(options.algorithms)
    if hashes == []:
        return
    skipHashes = ParseHashList(options.skip)
    validateHashes = ParseHashList(options.validate)
    if not options.quiet and not options.csv and oBinaryFile.extracted:
        print('%sExtracted!' % (prefix))
    if options.block == 0:
        row = [filename]
        for name in hashes:
            if not name in dFileHashes:
                dFileHashes[name] = {}
            dHashes[name].update(data)
            hashdigest = dHashes[name].hexdigest()
            if options.uppercase:
                hashdigest = hashdigest.upper()
            if hashdigest.lower() in skipHashes:
                if not options.quiet and not options.csv:
                    print('%sskipped' % (prefix))
            else:
                dFileHashes[name][hashdigest] = dFileHashes[name].get(hashdigest, []) + [filename]
                if options.quiet:
                    print(hashdigest)
                elif options.csv:
                    row.append(hashdigest)
                else:
                    validated = ''
                    if hashdigest.lower() in validateHashes:
                        validated = ' (validated)'
                    print('%s%-6s: %s%s' % (prefix, name, hashdigest, validated))
        if options.csv:
            print(MakeCSVLine(row, SEPARATOR, QUOTE))
    else:
        dBlockHashes = {name: {} for name in hashes}
        countBlocks = 0
        output = []
        while len(data) > 0:
            block = data[:options.block]
            data = data[options.block:]
            countBlocks += 1
            for name in hashes:
                oHash = dHashes[name].copy()
                oHash.update(block)
                hashdigest = oHash.hexdigest()
                if options.uppercase:
                    hashdigest = hashdigest.upper()
                output.append('%s%-6s: %6d %s' % (prefix, name, len(block), hashdigest))
                dBlockHashes[name][hashdigest] = dBlockHashes[name].get(hashdigest, 0) + 1
        if countBlocks <= 1:
            for line in output:
                print(line)
            return
        if max(len(value) for value in dBlockHashes.values()) > 1:
            for line in output:
                print(line)
        for name in hashes:
            if len(dBlockHashes[name]) == 1:
                print('%sSummary %s values: all blocks are identical (%d blocks in total)' % (prefix, name, countBlocks))
                print('%s %s' % (prefix, dBlockHashes[name].keys()[0]))
            elif len(dBlockHashes[name]) == countBlocks:
                print('%sSummary %s values: all %d blocks are different' % (prefix, name, countBlocks))
            else:
                print('%sSummary %s values: %d different blocks (%d blocks in total)' % (prefix, name, len(dBlockHashes[name]), countBlocks))

def HashFiles(filenames, options):
    dFileHashes = {}
    for filename, cutexpression in filenames:
        if filename != '' and len(filenames) > 1 and not options.quiet and not options.csv:
            print('File: %s' % filename)
            prefix = ' '
        else:
            prefix = ''
        HashSingle(filename, cutexpression, prefix, dFileHashes, options)
    if options.compare:
        print('\nFile hash summary:')
        if len(dFileHashes) == 0:
            print(' No files were hashed')
        else:
            hashes, _ = GetHashObjects(options.algorithms)
            for name in hashes:
                dHashes = dFileHashes[name]
                if len(dHashes) == len(filenames):
                    print(' All files have different %s hashes' % name)
                else:
                    uniques = []
                    items = sorted(dHashes.items(), key=lambda item: len(item[1]), reverse=True)
                    for hashvalue, filenamesvalue in items:
                        if len(filenamesvalue) > 1:
                            print(' Files (%d) with identical %s hash value %s:' % (len(filenamesvalue), name, hashvalue))
                            for filename in filenamesvalue:
                                print('  %s' % filename)
                        else:
                            uniques.append(filenamesvalue[0])
                    if len(uniques) > 0:
                        print(' Files with unique %s hash value:' % (name))
                        for filename in uniques:
                            print('  %s' % filename)
                if len(dHashes) == 1:
                    print(' All %s hashes are identical' % name)
                else:
                    print(' There are %d different %s hashes' % (len(dHashes), name))

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file|cut-expression ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--algorithms', default='', help='Hash algorithms to use (default md5;sha1;sha256)')
    oParser.add_option('-u', '--uppercase', action='store_true', default=False, help='Display hash values in uppercase')
    oParser.add_option('-c', '--compare', action='store_true', default=False, help='Compare file hash values (except in block mode)')
    oParser.add_option('-b', '--block', default='', help='Block size for hashing')
    oParser.add_option('-s', '--skip', default='', help='Hashes to skip (except in block mode)')
    oParser.add_option('-v', '--validate', default='', help='Hashes to validate (except in block mode)')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='Just print hash values (except in block mode)')
    oParser.add_option('-C', '--csv', action='store_true', default=False, help='Output CSV')
    oParser.add_option('--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--recursedir', action='store_true', default=False, help='Recurse directories (wildcards allowed, here files (@...) not)')

    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.block == '':
        options.block = 0
    else:
        tokens = Tokenize(options.block)
        try:
            number = InterpretNumber(tokens[0])
        except:
            number = None
        if len(tokens) != 1 or number == None or number < 0:
            print('Error: option block has to be a positive integer: %s' % options.block)
            return
        options.block = number

    if options.compare and options.block > 0:
        print('Error: options compare and block are mutually exclusive')
        return

    HashFiles(ExpandFilenameArguments(args, options.literalfilenames, options.recursedir), options)

if __name__ == '__main__':
    Main()
