#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Analyze Cobalt Strike beacons'
__author__ = 'Didier Stevens'
__version__ = '0.0.20'
__date__ = '2023/10/15'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2019/05/15: start
  2019/05/18: continue
  2019/05/25: continue
  2019/12/06: continue
  2019/12/07: continue
  2019/12/17: continue
  2020/02/03: 0.0.2 some changes for CS4: xor key is '.' in stead of 'i'
  2020/10/11: 0.0.3 Python 3 fixes
  2020/10/17: improve parsing
  2020/10/18: updated some config identifiers: found https://github.com/JPCERTCC/aa-tools https://github.com/sysopfb/malware_decoders/tree/master/cs_beacon https://github.com/Sentinel-One/CobaltStrikeParser
  2020/10/21: Python 3 fix in cBinaryFile
  2020/10/28: refactoring
  2020/10/29: man
  2020/11/04: added xor chain decoding
  2020/11/07: 0.0.4 updated shellcode analysis
  2020/11/12: updated shellcode analysis
  2020/11/16: added option -l
  2020/11/17: continue
  2020/11/29: added rule_shellcode_00_end
  2021/02/13: 0.0.5 updated shellcode analysis (+ Python 3 fix); added XORChain analysis for PE sections; remove duplicate configs when dumping raw
  2021/03/06: added option -c
  2021/03/25: 0.0.6 fix for provided sample
  2021/04/06: fix
  2021/04/28: added option -J
  2021/04/30: CS version guessing
  2021/05/02: fix
  2021/05/15: continue JSON output
  2021/06/14: updated man with 1768.json info
  2021/10/10: 0.0.8 1768.json improvements
  2021/10/17: 0.0.9 added malleable instructions decoding
  2021/11/01: refactoring instructions decoding
  2021/11/05: 0.0.10 cOutput replacements
  2021/11/07: added FinalTests
  2021/11/14: added DNS fields
  2021/11/17: added missing field names (ebook FINDING BEACONS IN THE DARK)
  2021/12/12: 0.0.11 added 1768b.json support
  2022/02/22: 0.0.12 added private key to 1768.json (provided by alexzorila); fix json output; pyzipper support
  2022/04/15: 0.0.13 added option -H and IdentifyShellcode
  2022/04/16: continue IdentifyShellcode
  2022/05/20: 0.0.14 skipping 0x20 bytes
  2022/07/31: 0.0.15 update class cAPIOptions
  2022/08/17: added option --sanitycheck; refactored FinalTests
  2022/08/20: 0.0.16 added output instructions to JSON output
  2022/08/30: 0.0.17 added option -x
  2023/04/02: updated man page
  2023/04/03: 0.0.18 cleanup debugging
  2023/04/27: 0.0.19 added LSFIF
  2023/10/06: 0.0.20 updated APIAnalyze
  2023/10/15: added runtime config parsing

Todo:

"""

import optparse
import sys
import os
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
import fnmatch
import json
import time
import hashlib
try:
    from minidump.minidumpfile import MinidumpFile
    from minidump.streams import MemoryInfoListStream
except ImportError:
    pass
try:
    import pyzipper as zipfile
except ImportError:
    import zipfile
if sys.version_info[0] >= 3:
    from io import BytesIO as DataIO
else:
    from cStringIO import StringIO as DataIO
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
try:
    import pefile
    import peutils
except ImportError:
    print('Missing pefile and/or peutils Python module, please check if it is installed.')
    sys.exit()

def PrintManual():
    manual = r'''
Manual:

1768 Kelvin is the melting point of the metal cobalt.

This tool decrypts and dumps the configuration of Cobalt Strike Windows beacons (PE files), shellcode and memory dumps.

Use option -x to try all 256 xor keys for the configuration (not only 0x2e and 0x69).

Option -s (--select) can be used to select a particular configuration item (by decimal of hexadecimal number) for more information. For the moment, this option displays the complete item's data (hexadecimal in cleartext, encoded with 'i' (0x69) and encoded with '.' (0x2e). These hexadecimal values  can be used to create detection rules, like YARA rules.

Option -l (--licenseid) is used to generate YARA rules to detect a beacon or shellcode with the given license ID. The id can be provided as an integer or an hexadecimal value (prefixed by 0x).
More than one license id can be provided: separate them by commas (,).
Each license id can be previded by a name for the license is (use : as a separator).
Example : 1768.py -l ATP_1:12345678,pentester_2:87654321

Option -c (--csv) is used to output the config parameters in CSV format.

Option -J (--jsonoutput) is used to output the config parameters in JSON format.

Use option -H to display the hashes of the analyzed file.

Option -S (--sanitycheck) performs a sanity check on the extracted configuration, and ignores the extracted configuration when it does not pass a sanity check.
The sanity check checks for the presence of config values 1 and 7, and check if their values are plausible:
1 -> known payload type
7 -> public key starts with 308

Option -V (--verbose) produces more output:
- verbosity for config values (like the private key for leaked keys)
- hex/ascii dump of found signatures

When a signature is found, the longest ASCII string in front of the signature (256 bytes span) is included, like this:
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x122f12d31 (LSFIF: b'!#ALF:Y2V:Elastic/HKTL_CobaltStrike_Beacon_4_2_Decrypt')
LSFIF is abbreviation Longest String Found In Front.

A JSON file with name 1768.json placed in the same directory as 1768.py will be used to enhance fields with information, like the license-id field.

It reads one or more files or stdin. This tool is very versatile when it comes to handling files, later full details will be provided.

This Python script was first developed with Python 2.7 and tested with Python 2.7 and 3.7, now it is developed with Python 3.9 and tested with Python 3.9.

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
It uses built-in Python module zipfile, unless module pyzipper is installed. Module pyzipper adds AES support, and can be installed with pip (Python 3 only).
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

To prevent the tool from processing file arguments with wildcard characters or special initial characters (@ and #) differently, but to process them as normal files, use option --literalfilenames.

The content of folders can be processed too: use option --recursedir and provide folder names as argument. Wildcards and here files (for folder names) can be used too.

File arguments that start with character # have special meaning. These are not processed as actual files on disk (except when option --literalfilenames is used), but as file arguments that specify how to "generate" the file content.

File arguments that start with #, #h#, #b# or #e# are used to "generate" the file content.
Arguments that start with #c# are not file arguments, but cut operators (explained later).
Arguments that start with #f# are not file arguments, but flags (explained later).

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
This cut-expression can be used to dump the first 256 bytes of a PE file located inside the file content: ['MZ']:0x100l
This cut-expression can be used to dump the OLE file located inside the file content: [d0cf11e0]:

A flag argument starts with #f# and is passed on for all files that are provided after the flag argument. It can be used to change the behavior of the tool for certain files.
Example:

tool.py data-1.bin #f#-l data-2.bin

data-2.bin will be processed differently (using flag option -l) than file data-1.bin.

With option --jsoninput, the tool will parse the output produced by another tool using option --jsonoutput.
Example:
zipdump.py --jsonoutput Book1.xlsm | file-magic.py --jsoninput
[Content_Types].xml XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
_rels/.rels XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/_rels/workbook.xml.rels  XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/workbook.xml XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/drawings/drawing1.xml  XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/worksheets/_rels/sheet1.xml.rels XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/theme/theme1.xml XML 1.0 document, UTF-8 Unicode text, with very long lines, with CRLF line terminators
xl/styles.xml XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/worksheets/sheet1.xml  XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/vbaProject.bin Composite Document File V2 Document, Cannot read section info
xl/drawings/vmlDrawing1.vml ASCII text, with CRLF line terminators
docProps/app.xml  XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
xl/ctrlProps/ctrlProp1.xml  XML 1.0 document, ASCII text, with CRLF line terminators
docProps/core.xml XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators

In this example, zipdump is used to produce JSON data with the content of each file contained inside file Book1.xlsm (a ZIP container), which is then consumed by file-magic.py to identify (libmagic) the type of each file.

With option --ignoreprocessingerrors, the tool will continue processing the next file when an error occurs while processing the current file. Files that can not be opened will always be skipped to move to the next file.

Option --logfile direct the tool to create a logfile, and option --logcomment can be used to add a comment to the log file. The log file will contain metadata and a list of processed files, it does not contain processing results.
It is best to use this option when option --ignoreprocessingerrors is used, to have a record of file processing errors.

The lines are written to standard output, except when option -o is used. When option -o is used, the lines are written to the filename specified by option -o.
Filenames used with option -o starting with # have special meaning.
#c#example.txt will write output both to the console (stdout) and file example.txt.
#g# will write output to a file with a filename generated by the tool like this: toolname-date-time.txt.
#g#KEYWORD will write output to a file with a filename generated by the tool like this: toolname-KEYWORD-date-time.txt.
Use #p#filename to display execution progress.
To process several files while creating seperate output files for each input file, use -o #s#%f%.result *.
This will create output files with the name of the inputfile and extension .result.
There are several variables available when creating separate output files:
 %f% is the full filename (with directory if present)
 %b% is the base name: the filename without directory
 %d% is the directory
 %r% is the root: the filename without extension
 %ru% is the root made unique by appending a counter (if necessary)
 %e% is the extension
#h# is like the head command: only the first 10 lines will be outputed.
#t# is like the tail command: only the last 10 lines will be outputed.
Most options can be combined, like #ps# for example.
#l# is used for literal filenames: if the output filename has to start with # (#example.txt for example), use filename #l##example.txt for example.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

DEFAULT_SEPARATOR = ','
QUOTE = '"'

START_CONFIG = b'\x00\x01\x00\x01\x00\x02'
START_CONFIG_I = b'ihihik'
START_CONFIG_DOT = b'././.,'

ERROR_NO_CONFIG = 'Error: config not found'
ERROR_SANITY_CHECK = 'Error: config does not pass sanity check'

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 String If Python 3
def C2SIP3(bytes):
    if sys.version_info[0] > 2:
        return ''.join([chr(byte) for byte in bytes])
    else:
        return bytes

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

def P23Ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)

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
            number = CheckNumber(arguments[0], minimum=1, maximum=255)
            if number == None:
                return None
            if len(arguments) == 1:
                decoded += chr(number)
            else:
                number2 = CheckNumber(arguments[1], minimum=1, maximum=255)
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

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

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

class cExpandFilenameArguments():
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False, expressionprefix=None, flagprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ''
        self.filenameexpressionsflags = []
        self.expressionprefix = expressionprefix
        self.flagprefix = flagprefix
        self.literalfilenames = literalfilenames

        expression = ''
        flag = ''
        if len(filenames) == 0:
            self.filenameexpressionsflags = [['', '', '']]
        elif literalfilenames:
            self.filenameexpressionsflags = [[filename, '', ''] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix != None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix):]
                elif flagprefix != None and dirwildcard.startswith(flagprefix):
                    flag = dirwildcard[len(flagprefix):]
                else:
                    if dirwildcard.startswith('@'):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressionsflags.append([filename, expression, flag])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressionsflags.append([dirwildcard, expression, flag])
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
                                self.filenameexpressionsflags.append([os.path.join(path, filename), expression, flag])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix != None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix):]
                elif flagprefix != None and filename.startswith(flagprefix):
                    flag = filename[len(flagprefix):]
                else:
                    self.filenameexpressionsflags.append([filename, expression, flag])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressionsflags) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressionsflags == [] and (expression != '' or flag != ''):
            self.filenameexpressionsflags = [['', expression, flag]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ('?' in filename or '*' in filename or ('[' in filename and ']' in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression, flag in self.filenameexpressionsflags:
            hashfile = False
            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except:
                pass
            if filename == '' or hashfile:
                valid.append([filename, expression, flag])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression, flag])
        self.filenameexpressionsflags = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += 'The following files do not exist and will be skipped: ' + ' '.join(doesnotexist) + '\n'
        if len(isnotafile) > 0:
            self.warning = True
            self.message += 'The following files are not regular files and will be skipped: ' + ' '.join(isnotafile) + '\n'

    def Filenames(self):
        if self.expressionprefix == None:
            return [filename for filename, expression, flag in self.filenameexpressionsflags]
        else:
            return self.filenameexpressionsflags

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
            asciiDump += IFF(b >= 32 and b < 128, chr(b), '.')
        if countRLE > 0:
            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
        oDumpStream.Addline(self.CombineHexAscii(position + hexDump, asciiDump))
        return oDumpStream.Content()

    def Base64Dump(self, nowhitespace=False):
        encoded = binascii.b2a_base64(self.data)
        if nowhitespace:
            return encoded
        encoded = encoded.strip()
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

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != '':
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]

class cVariables():
    def __init__(self, variablesstring='', separator=DEFAULT_SEPARATOR):
        self.dVariables = {}
        if variablesstring == '':
            return
        for variable in variablesstring.split(separator):
            name, value = VariableNameValue(variable)
            self.dVariables[name] = value

    def SetVariable(self, name, value):
        self.dVariables[name] = value

    def Instantiate(self, astring):
        for key, value in self.dVariables.items():
            astring = astring.replace('%' + key + '%', value)
        return astring

class cOutput():
    def __init__(self, filenameOption=None):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.head = False
        self.headCounter = 0
        self.tail = False
        self.tailQueue = []
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')

        self.dReplacements = {}

    def Replace(self, line):
        for key, value in self.dReplacements.items():
            line = line.replace(key, value)
        return line

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    elif switch == 'h':
                        self.head = True
                    elif switch == 't':
                        self.tail = True
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def LineSub(self, line, eol):
        line = self.Replace(line)
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def Line(self, line, eol='\n'):
        if self.head:
            if self.headCounter < 10:
                self.LineSub(line, eol)
            elif self.tail:
                self.tailQueue = self.tailQueue[-9:] + [[line, eol]]
            self.headCounter += 1
        elif self.tail:
            self.tailQueue = self.tailQueue[-9:] + [[line, eol]]
        else:
            self.LineSub(line, eol)

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.head and self.tail and len(self.tailQueue) > 0:
            self.LineSub('...', '\n')

        for line, eol in self.tailQueue:
            self.LineSub(line, eol)

        self.headCounter = 0
        self.tailQueue = []

        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

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

def MakeCSVLine(row, separator=',', quote='"'):
    return separator.join([Quote(value, separator, quote) for value in row])

class cLogfile():
    def __init__(self, keyword, comment):
        self.starttime = time.time()
        self.errors = 0
        if keyword == '':
            self.oOutput = None
        else:
            self.oOutput = cOutput('%s-%s-%s.log' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], keyword, self.FormatTime()))
        self.Line('Start')
        self.Line('UTC', '%04d%02d%02d-%02d%02d%02d' % time.gmtime(time.time())[0:6])
        self.Line('Comment', comment)
        self.Line('Args', repr(sys.argv))
        self.Line('Version', __version__)
        self.Line('Python', repr(sys.version_info))
        self.Line('Platform', sys.platform)
        self.Line('CWD', repr(os.getcwd()))

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def Line(self, *line):
        if self.oOutput != None:
            self.oOutput.Line(MakeCSVLine((self.FormatTime(), ) + line, DEFAULT_SEPARATOR, QUOTE))

    def LineError(self, *line):
        self.Line('Error', *line)
        self.errors += 1

    def Close(self):
        if self.oOutput != None:
            self.Line('Finish', '%d error(s)' % self.errors, '%d second(s)' % (time.time() - self.starttime))
            self.oOutput.Close()

def CalculateByteStatistics(dPrevalence=None, data=None):
    averageConsecutiveByteDifference = None
    if dPrevalence == None:
        dPrevalence = {iter: 0 for iter in range(0x100)}
        sumDifferences = 0.0
        previous = None
        if len(data) > 1:
            for byte in data:
                byte = C2IIP2(byte)
                dPrevalence[byte] += 1
                if previous != None:
                    sumDifferences += abs(byte - previous)
                previous = byte
            averageConsecutiveByteDifference = sumDifferences /float(len(data)-1)
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
    countHexadecimalBytes = 0
    countBASE64Bytes = 0
    for iter in range(0x30, 0x3A):
        countHexadecimalBytes += dPrevalence[iter]
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x41, 0x47):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x61, 0x67):
        countHexadecimalBytes += dPrevalence[iter]
    for iter in range(0x41, 0x5B):
        countBASE64Bytes += dPrevalence[iter]
    for iter in range(0x61, 0x7B):
        countBASE64Bytes += dPrevalence[iter]
    countBASE64Bytes += dPrevalence[ord('+')] + dPrevalence[ord('/')] + dPrevalence[ord('=')]
    entropy = 0.0
    for iter in range(0x100):
        if dPrevalence[iter] > 0:
            prevalence = float(dPrevalence[iter]) / float(sumValues)
            entropy += - prevalence * math.log(prevalence, 2)
            countUniqueBytes += 1
    return sumValues, entropy, countUniqueBytes, countNullByte, countControlBytes, countWhitespaceBytes, countPrintableBytes, countHighBytes, countHexadecimalBytes, countBASE64Bytes, averageConsecutiveByteDifference

def GetChunk(position, data):
    return [data[:position], data[position:]]

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

class UnpackErrorNotEnoughData(Exception):

    pass

def Unpack(format, data):
    size = struct.calcsize(format)
    if len(data) < size:
        raise UnpackErrorNotEnoughData()
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

def Represent(data):
    if sum([ord(c) for c in data]) == 0:
        return '(NULL ...)'
    else:
        return repr(data.rstrip('\x00'))

def PrefixIfNeeded(string, prefix=' '):
    if string == '':
        return string
    else:
        return prefix + string

def Xor(data, key):
    data = C2SIP3(data)
    key = C2SIP3(key)
    return C2BIP3(''.join(chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data))))

def FindAll(data, sub):
    result = []
    start = 0
    while True:
        position = data.find(sub, start)
        if position == -1:
            return result
        result.append(position)
        start = position + 1

def FindAllList(data, searches):
    result = []
    for element in searches:
        result.extend(FindAll(data, element))
    return sorted(list(set(result)))

def DecodeSectionnameIfNeeded(name):
    if len(name) == 0 or name.startswith('.'):
        return name
    xorkey = ord(name[0]) ^ ord('.')
    newname = ''.join([chr(ord(c) ^ xorkey) for c in name]).rstrip('\x00')
    return newname

def GetDataSection(data):
    sectionnames = []
    try:
        oPE = pefile.PE(data=data)
    except Exception as e:
        return e.value, None
    for section in oPE.sections:
        if sys.version_info[0] >= 3:
            sectionname = ''.join(filter(lambda c:c != '\0', str(section.Name.decode('unicode_escape'))))
        else:
            sectionname = ''.join(filter(lambda c:c != '\0', section.Name))
        sectionnames.append(repr(sectionname))
        if DecodeSectionnameIfNeeded(sectionname) == '.data':
            return None, section.get_data()
    return '.data section not found: ' + ' '.join(sectionnames), None

def GetXorChainSection(data):
    try:
        oPE = pefile.PE(data=data)
    except Exception as e:
        return None, e.value
    for section in oPE.sections:
        extracted, messages = TryXORChainDecoding(section.get_data())
        if messages != []:
            return extracted, messages
    return None, None

def StatisticalSearch(payloadsectiondata, key):
    start = None
    end = None
    position = 0
    while len(payloadsectiondata) > 8:
        block, payloadsectiondata = GetChunk(8, payloadsectiondata)
        if sum([IFF(c == key, 1, 0) for c in block]) > 2:
            if start == None:
                start = position
                end = position + 7
            else:
                end = position + 7
        position += 8
    return start, end

def Bytes2IPv4(data):
    return '%d.%d.%d.%d' % (P23Ord(data[0]), P23Ord(data[1]), P23Ord(data[2]), P23Ord(data[3]))

def FindAF_INET_PORT(operand):
    if P23Ord(operand[0]) != 2:
        return ''
    if P23Ord(operand[1]) != 0:
        return ''
    return '%d' % struct.unpack('>H', operand[2:4])[0]

def IdentifyShellcode(shellcode):
    if hashlib.sha256(shellcode[:346]).hexdigest() == '946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c':
        return 'CS psexec psh x86 shellcode, opens named pipe'
    elif hashlib.sha256(shellcode[:191]).hexdigest() == '02fd615831f5cc22d83ad681d33159d232afc3b18b69f647f1726280e2d7e3f3':
        return 'CS reverse http x86 shellcode'
    elif hashlib.sha256(shellcode[:271]).hexdigest() == 'bf413ba9b63b6777c4765581bf42c1fdb119f1ed22836cfaa80e616e2a3bf795':
        return 'CS reverse http x64 shellcode'
    elif hashlib.sha256(shellcode[:196]).hexdigest() == '52230666746fa8c9ec635083b05943d02bfe516fc45ea9c87eef300b9cd064e8':
        return 'CS reverse https x86 shellcode'
    elif hashlib.sha256(shellcode[:274]).hexdigest() == 'acffe4f9fd8f82044772627a4174f14abf873a8e783c31353bf094118f3c1706':
        return 'CS reverse https x64 shellcode'
    elif hashlib.sha256(shellcode[:330]).hexdigest() == 'a82872e2d839cd2ee1b0c2324b83f2686284ebe3eef5e9fb0c9e97db8d86cbf4':
        return 'CS DNS x86 shellcode'
    return ''

def AnalyzeShellcode(shellcode, oOutput):
    dInstructions = {b'\x68': 'push', b'\xB8': 'mov eax'}
    dJSONData = GetJSONData()
    dLookupValues = dJSONData.get('dLookupValues', {})

    identification = IdentifyShellcode(shellcode)
    if identification != '':
        oOutput.Line('Identification: %s' % identification)
    position = shellcode.rfind(b'\xFF\xFF')
    if position != -1:
        parameters = shellcode[position+2:]
        position00 = parameters.find(b'\x00')
        remainder = b''
        if position00 != -1:
            remainder = parameters[position00 + 1:]
            parameters = parameters[:position00]
        oOutput.Line('Parameter: %d %s' % (position, repr(parameters)))
        if len(remainder) == 4:
            licenseid = struct.unpack('>I',remainder)[0]
            info = 'license-id: %d %d' % (position + position00 + 1, licenseid)
            info += LookupValue("37", '%d' % licenseid, dLookupValues)
            oOutput.Line(info)
    for pushPosition in FindAllList(shellcode, dInstructions.keys()):
        if pushPosition + 5 <= len(shellcode):
            if position == -1:
                operand = shellcode[pushPosition + 1:pushPosition + 5]
                oOutput.Line('%-10s: %5d %10d %5s %-16s %s' % (dInstructions[shellcode[pushPosition:pushPosition+1]], pushPosition, struct.unpack('<I', operand)[0], FindAF_INET_PORT(operand), Bytes2IPv4(operand), repr(shellcode[pushPosition:pushPosition + 5])))
            elif shellcode[pushPosition + 3:pushPosition + 5] == b'\x00\x00':
                oOutput.Line('%-10s: %5d %10d %s' % (dInstructions[shellcode[pushPosition:pushPosition+1]], pushPosition, struct.unpack('<H', shellcode[pushPosition + 1:pushPosition + 3])[0], repr(shellcode[pushPosition:pushPosition + 5])))

    for str in ExtractStringsASCII(shellcode):
        if len(str) == 5 and str.startswith(b'/') or str.startswith(b'User-Agent: ') or str.startswith(b'Mozilla/'):
            positions = FindAll(shellcode, str)
            oOutput.Line('String: %s %s' % (','.join(['%d' % position for position in positions]),str))

REGEX_STANDARD = b'[\x09\x20-\x7E]'

def ExtractStringsASCII(data):
    regex = REGEX_STANDARD + b'{%d,}'
    return re.findall(regex % 1, data)

def LookupConfigValue(id, value):
    dConfigValues = {
        0x0001: {
            0: 'windows-beacon_http-reverse_http',
            1: 'windows-beacon_dns-reverse_http',
            2: 'windows-beacon_smb-bind_pipz',
            4: 'windows-beacon_tcp-reverse_tcp',
            8: 'windows-beacon_https-reverse_https',
            16: 'windows-beacon_tcp-bind_tcp',
            32: 'to be determined',
        },
        0x0023: {
            1: 'no proxy',
            2: 'IE settings',
            4: 'hardcoded proxy',
        },
        0x002b: {
            0x01: 'PAGE_NOACCESS',
            0x02: 'PAGE_READONLY',
            0x04: 'PAGE_READWRITE',
            0x08: 'PAGE_WRITECOPY',
            0x10: 'PAGE_EXECUTE',
            0x20: 'PAGE_EXECUTE_READ',
            0x40: 'PAGE_EXECUTE_READWRITE',
            0x80: 'PAGE_EXECUTE_WRITECOPY',
        },
    }
    return PrefixIfNeeded(dConfigValues[id].get(value, ''))

def ConvertIntToIPv4(value):
    return ' %d.%d.%d.%d' % (C2IIP2(value[0]), C2IIP2(value[1]), C2IIP2(value[2]), C2IIP2(value[3]))

def ToHexadecimal(value):
    if isinstance(value, int):
        return '%x' % value
    else:
        return binascii.b2a_hex(value).decode()

def LookupValue(number, value, dInfo, verbose=False):
    lookup = ''
    if number in dInfo:
        lookup = dInfo[number].get(value, '')
    if isinstance(lookup, dict):
        message = lookup['normal']
        if verbose:
            message += ' (%s)' % lookup['verbose']
        lookup = message
    return PrefixIfNeeded(lookup)

def InterpretValue(info, number, value, dConfigValueInterpreter):
    interpreted = ''
    if number in dConfigValueInterpreter:
        interpreted = dConfigValueInterpreter[number](value)
    return info + interpreted

def GetScriptPath():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])

def DetermineCSVersionFromConfig(dJSON):
    maximumID = max(map(int, dJSON.keys()))
    if maximumID < 55:
        return ('3', maximumID)
    elif maximumID == 55:
        return ('4.0', maximumID)
    elif maximumID > 55 and maximumID < 58:
        return ('4.1', maximumID)
    elif maximumID == 58:
        return ('4.2', maximumID)
    elif maximumID == 70:
        return ('4.3', maximumID)
    else:
        return ('4.4', maximumID)

def SanityCheckExtractedConfig(dJSON):
    if not 1 in dJSON:
        return False
    if not 7 in dJSON:
        return False
    if LookupConfigValue(1, dJSON[1]['rawvalue']) == '':
        return False
    if not isinstance(dJSON[7]['rawvalue'], str):
        return False
    if not dJSON[7]['rawvalue'].startswith('308'):
        return False
    return True

def GetJSONData():
    filename = os.path.join(GetScriptPath(), '1768b.json')
    if os.path.isfile(filename):
        return json.load(open(filename, 'r'))
    filename = os.path.join(GetScriptPath(), '1768.json')
    if os.path.isfile(filename):
        return json.load(open(filename, 'r'))
    return {}

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

# https://www.usualsuspect.re/article/cobalt-strikes-malleable-c2-under-the-hood
INSTRUCTION_TYPE_MALLEABLE_C2 = 1
INSTRUCTION_TYPE_GET = 2
INSTRUCTION_TYPE_POST = 3

INSTRUCTION_NONE = 0
INSTRUCTION_APPEND = 1
INSTRUCTION_PREPEND = 2
INSTRUCTION_BASE64 = 3
INSTRUCTION_PRINT = 4
INSTRUCTION_PARAMETER = 5
INSTRUCTION_HEADER = 6
INSTRUCTION_BUILD = 7
INSTRUCTION_NETBIOS = 8
INSTRUCTION_CONST_PARAMETER = 9
INSTRUCTION_CONST_HEADER = 10
INSTRUCTION_NETBIOSU = 11
INSTRUCTION_URI_APPEND = 12
INSTRUCTION_BASE64URL = 13
INSTRUCTION_STRREP = 14
INSTRUCTION_MASK = 15
INSTRUCTION_CONST_HOST_HEADER = 16

def DecodeInstructions(value, instructionsType):
    oStruct = cStruct(value)
    instructions = []
    opcodes = []
    buildFlag = False
    while oStruct.Length() >= 4:
        opcode = oStruct.Unpack('>I')
        if buildFlag and opcode in [0, 6, 7, 10, 16]:
            instructions.append('Build End')
            opcodes.append(['7', 'End'])
            buildFlag = False
        if opcode == INSTRUCTION_NONE:
            break
        if opcode == INSTRUCTION_APPEND:
            if instructionsType == INSTRUCTION_TYPE_MALLEABLE_C2:
                operand = oStruct.Unpack('>I')
                instructions.append('Remove %d bytes from end' % operand)
                opcodes.append([str(opcode), str(operand)])
            else:
                operand = oStruct.GetString('>I').decode('latin')
                instructions.append('Append %s' % operand)
                opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_PREPEND:
            if instructionsType == INSTRUCTION_TYPE_MALLEABLE_C2:
                operand = oStruct.Unpack('>I')
                instructions.append('Remove %d bytes from begin' % operand)
                opcodes.append([str(opcode), str(operand)])
            else:
                operand = oStruct.GetString('>I').decode('latin')
                instructions.append('Prepend %s' % operand)
                opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_BASE64:
            instructions.append('BASE64')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_PRINT:
            instructions.append('Print')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_PARAMETER:
            operand = oStruct.GetString('>I').decode('latin')
            instructions.append('Parameter %s' % operand)
            opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_HEADER:
            operand = oStruct.GetString('>I').decode('latin')
            instructions.append('Header %s' % operand)
            opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_BUILD:
            buildFlag = True
            operand = oStruct.Unpack('>I')
            if instructionsType == INSTRUCTION_TYPE_POST:
                if operand == 0:
                    operand = 'SessionId'
                else:
                    operand = 'Output'
            else:
                operand = 'Metadata'
            instructions.append('Build %s' % operand)
            opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_NETBIOS:
            instructions.append('NETBIOS lowercase')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_CONST_PARAMETER:
            operand = oStruct.GetString('>I').decode('latin')
            instructions.append('Const_parameter %s' % operand)
            opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_CONST_HEADER:
            operand = oStruct.GetString('>I').decode('latin')
            instructions.append('Const_header %s' % operand)
            opcodes.append([str(opcode), operand])
        elif opcode == INSTRUCTION_NETBIOSU:
            instructions.append('NETBIOS uppercase')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_URI_APPEND:
            instructions.append('Uri_append')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_BASE64URL:
            instructions.append('BASE64 URL')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_STRREP:
            operand1 = oStruct.GetString('>I').decode('latin')
            operand2 = oStruct.GetString('>I').decode('latin')
            instructions.append('STRREP %s %s' % (operand1, operand2))
            opcodes.append([str(opcode), operand1, operand2])
        elif opcode == INSTRUCTION_MASK:
            instructions.append('XOR with 4-byte random key')
            opcodes.append([str(opcode)])
        elif opcode == INSTRUCTION_CONST_HOST_HEADER:
            operand = oStruct.GetString('>I').decode('latin')
            instructions.append('Const_host_header %s' % operand)
            opcodes.append([str(opcode), operand])
        else:
            instructions.append('Unknown instruction: 0x%02x' % opcode)
            opcodes.append([str(opcode)])

    result = []
    buildFlag = False
    for instruction in instructions:
        if instruction == 'Build End':
            result.append(build)
        elif instruction.startswith('Build '):
            build = [instruction]
            buildFlag= True
        elif buildFlag:
            build.append(instruction)
        else:
            result.append(instruction)
    instructions = result

    result = []
    buildFlag = False
    for opcode in opcodes:
        if opcode == ['7', 'End']:
            result.append(build)
        elif opcode[0] == '7':
            build = [opcode]
            buildFlag= True
        elif buildFlag:
            build.append(opcode)
        else:
            result.append(opcode)
    opcodes = result

    if instructionsType == INSTRUCTION_TYPE_MALLEABLE_C2:
        instructions = [['Transform Input'] + instructions]
        opcodes = [[['7', 'Input']] + opcodes]
    return [instructions, opcodes]

def DecodeMalleableC2Instructions(parameter):
    instructions, opcodes = DecodeInstructions(parameter, INSTRUCTION_TYPE_MALLEABLE_C2)
    buildOpcodes = ','.join([item for opcode in opcodes for item in opcode])
    return 'Instructions: ' + ','.join(instructions) + ' [7,Input,' + buildOpcodes + ']'

def AnalyzeEmbeddedPEFileSub(payloadsectiondata, options):
    result = []

    if options.xorkeys:
        for xorKey in range(256):
            xorKeyBytes = bytes([xorKey])
            startConfigXored = Xor(START_CONFIG, xorKeyBytes)
            for position in FindAll(payloadsectiondata, startConfigXored):
                result, dJSON = AnalyzeEmbeddedPEFileSub2(Xor(payloadsectiondata[position:position+0x10000], xorKeyBytes), result, options)
                if result != [ERROR_SANITY_CHECK]:
                    return result, dJSON
        return [result, {}]

    xorKey = b'i'
    config, startconfig, endconfig = CutData(Xor(payloadsectiondata, xorKey), '[000100010002]:')
    if len(config) == 0:
        xorKey = b'.'
        config, startconfig, endconfig = CutData(Xor(payloadsectiondata, xorKey), '[000100010002]:')
    if len(config) == 0:
        xorKey = b'i'
        startconfig, endconfig = StatisticalSearch(payloadsectiondata, xorKey)
        if startconfig == None:
            xorKey = b'.'
            startconfig, endconfig = StatisticalSearch(payloadsectiondata, xorKey)
        if startconfig == None:
            result.append(ERROR_NO_CONFIG)
            return [result, {}]
        else:
            result.append('Config found (statistical): xorkey %s 0x%08x 0x%08x' % (xorKey, startconfig, endconfig))
            result.append(cDump(Xor(payloadsectiondata[startconfig:endconfig + 1], xorKey)).HexAsciiDump(rle=True))
            return [result, {}]
#                result.append('Config found: 0x%08x 0x%08x %s' % (startconfig, endconfig, ' '.join(['0x%08x' % position for position in FindAll(payloadsectiondata, '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')])))
#                result.append('Config found: 0x%08x 0x%08x %s' % (startconfig, endconfig, ' '.join(['0x%08x' % position for position in FindAll(payloadsectiondata, '\x90\x01\x00\x00')])))
    result.append('Config found: xorkey %s 0x%08x 0x%08x' % (xorKey, startconfig, endconfig))
    data = config

    return AnalyzeEmbeddedPEFileSub2(data, result, options)

def AnalyzeEmbeddedPEFileSub2(data, result, options):
    dJSON = {}

    dConfigIdentifiers = {
        0x0001: 'payload type',
        0x0002: 'port',
        0x0003: 'sleeptime',
        0x0004: 'maxgetsize', #
        0x0005: 'jitter',
        0x0006: 'maxdns',
        0x0007: 'publickey',
        0x0008: 'server,get-uri',
        0x0009: 'useragent',
        0x000a: 'post-uri',
        0x000b: 'Malleable_C2_Instructions', #
        0x000c: 'http_get_header',
        0x000d: 'http_post_header',
        0x000e: 'SpawnTo', #
        0x000f: 'pipename',
        0x0010: 'killdate_year', #
        0x0011: 'killdate_month', #
        0x0012: 'killdate_day', #
        0x0013: 'DNS_Idle', #
        0x0014: 'DNS_Sleep', #
        0x0015: 'SSH_HOST', #
        0x0016: 'SSH_PORT', #
        0x0017: 'SSH_USER-NAME', #
        0x0018: 'SSH_PASSWORD', #
        0x0019: 'SSH_PUBKEY', #
        0x001a: 'get-verb',
        0x001b: 'post-verb',
        0x001c: 'HttpPostChunk', #
        0x001d: 'spawnto_x86',
        0x001e: 'spawnto_x64',
        0x001f: 'CryptoScheme', #
        0x0020: 'proxy',
        0x0021: 'proxy_username',
        0x0022: 'proxy_password',
        0x0023: 'proxy_type',
        0x0024: 'deprecated', #
        0x0025: 'license-id',
        0x0026: 'bStageCleanup', #
        0x0027: 'bCFGCaution', #
        0x0028: 'killdate',
        0x0029: 'textSectionEnd', #
        0x002a: 'ObfuscateSectionsInfo', #
        0x002b: 'process-inject-start-rwx',
        0x002c: 'process-inject-use-rwx',
        0x002d: 'process-inject-min_alloc',
        0x002e: 'process-inject-transform-x86',
        0x002f: 'process-inject-transform-x64',
        0x0030: 'DEPRECATED_PROCINJ_ALLOWED',
        0x0031: 'BIND_HOST',
        0x0032: 'UsesCookies',
        0x0033: 'process-inject-execute',
        0x0034: 'process-inject-allocation-method',
        0x0035: 'process-inject-stub',
        0x0036: 'HostHeader',
        0x0037: 'EXIT_FUNK',
        0x0038: 'SSH_BANNER',
        0x0039: 'SMB_FRAME_HEADER',
        0x003a: 'TCP_FRAME_HEADER',
        0x003b: 'HEADERS_TO_REMOVE',
        0x003c: 'DNS_beacon',
        0x003d: 'DNS_A',
        0x003e: 'DNS_AAAA',
        0x003f: 'DNS_TXT',
        0x0040: 'DNS_metadata',
        0x0041: 'DNS_output',
        0x0042: 'DNS_resolver',
        0x0043: 'DNS_STRATEGY',
        0x0044: 'DNS_STRATEGY_ROTATE_SECONDS',
        0x0045: 'DNS_STRATEGY_FAIL_X',
        0x0046: 'DNS_STRATEGY_FAIL_SECONDS',
        0x0047: 'MAX_RETRY_STRATEGY_ATTEMPTS',
        0x0048: 'MAX_RETRY_STRATEGY_INCREASE',
        0x0049: 'MAX_RETRY_STRATEGY_DURATION',
    }
    dConfigValueInterpreter = {
        0x0001: lambda value: LookupConfigValue(0x0001, value),
        0x0007: ToHexadecimal,
        0x000b: DecodeMalleableC2Instructions,
        0x0013: ConvertIntToIPv4,
        0x0023: lambda value: LookupConfigValue(0x0023, value),
        0x002b: lambda value: LookupConfigValue(0x002b, value),
        0x002c: lambda value: LookupConfigValue(0x002b, value),
    }
    dJSONData = GetJSONData()
    dLookupValues = dJSONData.get('dLookupValues', {})

    while len(data) >= 2:
        formatNumber = '>H'
        formatTypeLength = '>HH'
        ntlBytes = data[0:struct.calcsize(formatNumber) + struct.calcsize(formatTypeLength)]
        try:
            number, data = Unpack(formatNumber, data)
        except UnpackErrorNotEnoughData:
            break
        if number == 0:
            result.append('0x%04x' % number)
            break
        try:
            type, length, data = Unpack(formatTypeLength, data)
        except UnpackErrorNotEnoughData:
            break
        parameter, data = GetChunk(length, data)
        info = ''
        rawvalue = None
        if type == 1 and length == 2:
            identifier = struct.unpack('>H', parameter)[0]
            rawvalue = identifier
            info = InterpretValue('%d' % identifier, number, identifier, dConfigValueInterpreter)
        elif type == 2 and length == 4:
            if number in [0x44, 0x45, 0x46]:
                rawvalue = struct.unpack('>i', parameter)[0]
            else:
                rawvalue = struct.unpack('>I', parameter)[0]
            value = '%d' % rawvalue
            info = InterpretValue(value, number, parameter[0:4], dConfigValueInterpreter)
            info += LookupValue(str(number), value, dLookupValues, options.verbose)
        elif type == 3 and not number in [0x0b, 0x0c, 0x0d]:
            info = InterpretValue('', number, parameter, dConfigValueInterpreter)
            rawvalue = binascii.b2a_hex(parameter).decode()
            if info == '':
                info = Represent(C2SIP3(parameter))
            info += LookupValue(str(number), rawvalue, dLookupValues, options.verbose)

        resultNumber = '0x%04x' % number
        resultType = '0x%04x' % type
        resultLength = '0x%04x' % length
        resultID = dConfigIdentifiers.get(number, '')
        dJSON[number] = {'id': resultID, 'type': resultType, 'info': info, 'rawvalue': rawvalue}
        if options.csv:
            result.append(MakeCSVLine((resultNumber, resultID, resultType, resultLength, info)))
        else:
            resultID = ('%-' + str(max([len(value) for value in dConfigIdentifiers.values()])) + 's') % resultID
            result.append('%s %s %s %s%s' % (resultNumber, resultID, resultType, resultLength, PrefixIfNeeded(info)))
        if type == 3 and number in [0x0b, 0x0c, 0x0d]:
            instructions, opcodes = DecodeInstructions(parameter, {0x0b: INSTRUCTION_TYPE_MALLEABLE_C2, 0x0c: INSTRUCTION_TYPE_GET, 0x0d: INSTRUCTION_TYPE_POST}[number])
            for index, instruction in enumerate(instructions):
                if isinstance(instruction, str):
                    if options.csv:
                        result.append(MakeCSVLine(('', '', '', '', instruction)))
                    else:
                        result.append('  %s' % instruction)
                else:
                    buildOpcodes = ','.join([':'.join(opcode) for opcode in opcodes[index]])
                    if number in dJSON:
                        if dJSON[number]['info'] == '':
                            dJSON[number]['info'] = buildOpcodes
                        else:
                            dJSON[number]['info'] += ';' + buildOpcodes
                    else:
                        dJSON[number] = {'id': resultID, 'type': resultType, 'info': buildOpcodes, 'rawvalue': binascii.b2a_hex(parameter).decode()}
                    if options.csv:
                        result.append(MakeCSVLine(('', '', '', '', '%s:[%s]' % (instruction[0], buildOpcodes))))
                    else:
                        result.append('  %s: [%s]' % (instruction[0], buildOpcodes))
                    for buildStep in instruction[1:]:
                        if options.csv:
                            result.append(MakeCSVLine(('', '', '', '', buildStep)))
                        else:
                            result.append('   %s' % buildStep)
#            for string in ExtractStringsASCII(parameter):
#                if options.csv:
#                    result.append(MakeCSVLine(('', '', '', '', string.decode('utf8', 'surrogateescape')), ',', '"'))
#                else:
#                    result.append('  %s' % string.decode('utf8', 'surrogateescape'))

        if options.select != '':
            select = ParseInteger(options.select)
            if number == select:
                result.append(' Decoded:     %s' % ToHexadecimal(ntlBytes + parameter))
                result.append(" 'i'-encoded: %s" % ToHexadecimal(Xor(ntlBytes + parameter, b'i')))
                result.append(" '.'-encoded: %s" % ToHexadecimal(Xor(ntlBytes + parameter, b'.')))
    result.append('Guessing Cobalt Strike version: %s (max 0x%04x)' % DetermineCSVersionFromConfig(dJSON))
    sanityCheck = SanityCheckExtractedConfig(dJSON)
    result.append('Sanity check Cobalt Strike config: %s' % ('OK' if sanityCheck else 'NOK'))
    if options.sanitycheck and not sanityCheck:
        return [[ERROR_SANITY_CHECK], {}]
    return [result, dJSON]

def AnalyzeEmbeddedPEFile(payloadsectiondata, oOutput, options):
    result, dJSON = AnalyzeEmbeddedPEFileSub(payloadsectiondata, options)
    oOutput.JSON(dJSON)
    for line in result:
        oOutput.Line(line)

def DetectPEFile(data):
    if len(data) < 40:
        return False
    if data[0:2] != b'MZ':
        return False
    offsetbytes = data[0x3C:0x3C + 4]
    if len(offsetbytes) != 4:
        return False
    offset = struct.unpack('<I', offsetbytes)[0]
    if data[offset:offset + 2] != b'PE':
        return False
    return True

def StripLeadingNOPs(data):
    return data.lstrip(b'\x90')

def XORChainSlow(iKey, encodedData):
    decodedData = b''
    xorkey = iKey
    while len(encodedData) >= 4:
        encoded = struct.unpack('<I', encodedData[0:4])[0]
        decodedData += struct.pack('<I', encoded ^ xorkey)
        xorkey = encoded
        encodedData = encodedData[4:]
    return decodedData

def XORChainFast(iKey, encodedData):
    oDATA = DataIO()
    xorkey = iKey
    index = 0
    format = '<I'
    formatLength = struct.calcsize(format)
    while True:
        bytesInteger = encodedData[index:index + formatLength]
        if len(bytesInteger) != formatLength:
            break
        encoded = struct.unpack(format, bytesInteger)[0]
        oDATA.write(struct.pack(format, encoded ^ xorkey))
        xorkey = encoded
        index += formatLength
    return oDATA.getvalue()

def XORChain(iKey, encodedData):
    fast = XORChainFast(iKey, encodedData)
    return fast
    slow = XORChainSlow(iKey, encodedData)
    if slow != fast:
        raise Exception('slow != fast')
    return fast

def TryXORChainDecoding(data):
    if len(data) < 0x100:
        return data, []
    formatstring = '<II'
    formatLength = struct.calcsize(formatstring)
    startLength = 16
    for iIter in range(1, 0x1000):
        bytesValues = data[iIter:iIter + formatLength + startLength]
        if len(bytesValues) != formatLength + startLength:
            return data, []
        xorKey, xorEncodedLength = struct.unpack(formatstring, bytesValues[:formatLength])
        decodedLength = xorKey ^ xorEncodedLength
        decodedStart = XORChain(xorKey, bytesValues[formatLength:])
        if StripLeadingNOPs(decodedStart)[0:2] == b'MZ':
            decodedData = StripLeadingNOPs(XORChain(xorKey, data[iIter + formatLength:iIter + formatLength + decodedLength]))
            if DetectPEFile(decodedData):
                return decodedData, ['xorkey(chain): 0x%08x' % xorKey, 'length: 0x%08x' % decodedLength]
        if b'MZRE' in decodedStart or b'MZAR' in decodedStart:
            decodedData = XORChain(xorKey, data[iIter + formatLength:iIter + formatLength + decodedLength])
            if START_CONFIG_I in decodedData or START_CONFIG_DOT in decodedData:
                return decodedData, ['xorkey(chain): 0x%08x' % xorKey, 'length: 0x%08x' % decodedLength]

    return data, []

def TryExtractDecode(data):
    if DetectPEFile(data):
        return data, []
    extracted = StripLeadingNOPs(data)
    if DetectPEFile(extracted):
        return extracted, ['leading NOPs: 0x%04x' % (len(data) - len(extracted))]
    extracted, messages = TryXORChainDecoding(data)
    if DetectPEFile(extracted):
        return extracted, messages
    if START_CONFIG_I in extracted or START_CONFIG_DOT in extracted:
        return extracted, messages
    return data, []

def TestShellcodeHeuristic(data):
    return b'hwini' in data[:0x1000] or b'hws2_' in data[:0x1000] or (data[0:1] == b'\xFC' and len(data) < 0x1000)

def FinalTests(data, options, oOutput):
    dSignatures = {
        # https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures
        'Sleep mask 64-bit 4.2 deobfuscation routine': b'\x4C\x8B\x53\x08\x45\x8B\x0A\x45\x8B\x5A\x04\x4D\x8D\x52\x08\x45\x85\xC9\x75\x05\x45\x85\xDB\x74\x33\x45\x3B\xCB\x73\xE6\x49\x8B\xF9\x4C\x8B\x03',
        'Sleep mask 32-bit 4.2 deobfuscation routine': b'\x8B\x46\x04\x8B\x08\x8B\x50\x04\x83\xC0\x08\x89\x55\x08\x89\x45\x0C\x85\xC9\x75\x04\x85\xD2\x74\x23\x3B\xCA\x73\xE6\x8B\x06\x8D\x3C\x08\x33\xD2',

        'Public key config entry': b'\x00\x07\x00\x03\x01\x00\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81',
        'Public key header': b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81',
    }

    for name, signature in dSignatures.items():
        xorKeys = [b'\x00']
        if name == 'Public key config entry':
            xorKeys = [b'\x00', b'\x2e', b'\x69']
            if options.xorkeys:
                xorKeys = [bytes([iter]) for iter in range(256)]
        for xorKey in xorKeys:
            signatureXored = Xor(signature, xorKey)
            for position in FindAll(data, signatureXored):
                stringsInFront = sorted(ExtractStringsASCII(data[position-0x100:position]), key=len, reverse=True)
                if len(stringsInFront) > 0:
                    longestString = ' (LSFIF: %s)' % stringsInFront[0]
                else:
                    longestString = ''
                oOutput.Line('%s found: 0x%08x%s%s' % (name, position, IFF(xorKey == b'\x00', '', ' (xorKey %s)' % xorKey), longestString))
                if options.verbose:
                    oOutput.Line(cDump(data[position-0x100:position], '  ', position-0x100).HexAsciiDump(rle=True), eol='')
                    oOutput.Line('  ... signature ...')
                    oOutput.Line(cDump(data[position+len(signatureXored):position+len(signatureXored)+0x100], '  ', position+len(signatureXored)).HexAsciiDump(rle=True), eol='')

#a# this is a kludge, to fix later when I have time
def ProcessBinaryFileSub(sectiondata, data, oOutput, options):
    payloadType, payloadSize, intxorkey, id2, sectiondata = Unpack('<IIII', sectiondata)
    oOutput.Line('payloadType: 0x%08x' % payloadType)
    oOutput.Line('payloadSize: 0x%08x' % payloadSize)
    oOutput.Line('intxorkey: 0x%08x' % intxorkey)
    oOutput.Line('id2: 0x%08x' % id2)
    payload = Xor(sectiondata[:payloadSize], struct.pack('<I', intxorkey))
    if payloadSize > len(sectiondata):
        oOutput.Line('Error: payload size too large: 0x%08x' % payloadSize)
        oOutput.Line('.data section size: 0x%08x' % len(sectiondata))
        return False
    error, payloadsectiondata = GetDataSection(payload)
    if error != None:
        positionMZ = payload.find(b'MZ')
        if positionMZ != 0:
            if START_CONFIG_I in sectiondata or START_CONFIG_DOT in sectiondata or options.xorkeys:
                AnalyzeEmbeddedPEFile(data, oOutput, options)
            elif TestShellcodeHeuristic(payload):
                if IdentifyShellcode(payload) == '':
                    oOutput.Line('Probably found shellcode:')
                else:
                    oOutput.Line('Found shellcode:')
                AnalyzeShellcode(payload, oOutput)
                oOutput.Line(cDump(payload).HexAsciiDump(rle=False))
            elif positionMZ >= 0 and positionMZ < 0x20:
                oOutput.Line('MZ header found position %d' % positionMZ)
                AnalyzeEmbeddedPEFile(payload[positionMZ:], oOutput, options)
            elif len(payload) == 0:
                return False
            else:
                oOutput.Line('MZ header not found, truncated dump:')
                oOutput.Line(cDump(payload[:0x1000]).HexAsciiDump(rle=True))
                return False
        else:
            oOutput.Line('Error: embedded PE file error: %s' % error)
            return False
    else:
        AnalyzeEmbeddedPEFile(payloadsectiondata, oOutput, options)
    FinalTests(payload, options, oOutput)
    return True

# cfr blog post Hendrik Eckardt
def RuntimeAnalysis(datamdmp, dConfigs, oOutput, options):
    listData = []
    oMinidumpFile = MinidumpFile.parse_bytes(datamdmp)
    oget_buffered_reader = oMinidumpFile.get_reader().get_buffered_reader()
    for info in oMinidumpFile.memory_info.infos:
#        print(info.Protect, info.BaseAddress, info.RegionSize, info.Type)
        try:
            oget_buffered_reader.move(info.BaseAddress)
        except Exception as e:
            if e.args[0].endswith(' is not in process memory space'):
#                print('Error: %s' % e.args[0])
                continue
            else:
                raise e
        try:
            bytesSegment = oget_buffered_reader.read(info.RegionSize)
            listData.append([['segment', info], bytesSegment])
        except OverflowError:
#            print('OverflowError') #a# handle overflow
            pass
        except Exception as e:
            if e.args[0] == 'Would read over segment boundaries!':
#                print('Error: %s' % e.args[0])
                pass
            else:
                raise e
    listData = sorted(listData, reverse=True, key=lambda item: len(item[1]))
    listData = [[dataInfo[1].BaseAddress, data] for dataInfo, data in listData]
    publickey = b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x81\x8D\x00\x30\x81\x89\x02\x81'
    for baseAddress, data in listData:
        positionsPublickey = FindAll(data, publickey)
        if len(positionsPublickey) > 0:
            for positionPublickey in positionsPublickey:
                addressPublickey = baseAddress + positionPublickey
                for packformatBits, packformat in {'32-bit': '<II', '64-bit': '<QQ'}.items():
                    packformatSize = struct.calcsize(packformat)
                    positionsPublickeyEntry = FindAll(data, struct.pack(packformat, 3, addressPublickey))
                    for positionPublickeyEntry in positionsPublickeyEntry:
                        positionRuntimeConfig = positionPublickeyEntry - 7 * packformatSize
                        oOutput.Line('Runtime config %s found: 0x%08x' % (packformatBits, addressPublickey))
                        oStruct = cStruct(data[positionRuntimeConfig:])
                        abConfig = b''
                        for counter in range(128):
                            entrytype, entrydata = oStruct.Unpack(packformat)
                            if entrytype == 0:
                                pass
                            elif entrytype == 3:
                                configItem = data[entrydata - baseAddress:]
                                if counter in [0x07, 0x0b, 0x0c, 0x0d]:
                                    configItem = configItem[:0x100]
                                else:
                                    configItem = configItem[:configItem.find(b'\x00')]
    #                            print('%04x %08x -> %s' % (counter, entrytype, configItem))
                                abConfig += struct.pack('>HHH', counter, entrytype, 0x100)
                                abConfig += configItem + b'\x00' * (0x100 - len(configItem))
                            elif entrytype == 1:
    #                            print('%04x %08x -> %d' % (counter, entrytype, entrydata))
                                abConfig += struct.pack('>HHH', counter, entrytype, 2)
                                abConfig += struct.pack('>H', entrydata)
                            elif entrytype == 2:
    #                            print('%04x %08x -> %d' % (counter, entrytype, entrydata))
                                abConfig += struct.pack('>HHH', counter, entrytype, 4)
                                abConfig += struct.pack('>I', entrydata)
                            else:
                                break
                        abConfig += struct.pack('>HHH', 0, 0, 0)
                        result, dJSON = AnalyzeEmbeddedPEFileSub2(abConfig, [], options)
                        configSha256 = hashlib.sha256(''.join(result).encode()).hexdigest()
                        if not configSha256 in dConfigs:
                            dConfigs[configSha256] = True
                            if result != [ERROR_SANITY_CHECK]:
                                oOutput.JSON(dJSON)
                                for line in result:
                                    oOutput.Line(line)

def ProcessBinaryFile(filename, content, cutexpression, flag, oOutput, oLogfile, options):
    if content == None:
        try:
            oBinaryFile = cBinaryFile(filename, C2BIP3(options.password), options.noextraction, options.literalfilenames)
        except:
            oLogfile.LineError('Opening file %s %s' % (filename, repr(sys.exc_info()[1])))
            return
        oLogfile.Line('Success', 'Opening file %s' % filename)
        try:
            data = oBinaryFile.read()
        except:
            oLogfile.LineError('Reading file %s %s' % (filename, repr(sys.exc_info()[1])))
            return
        data = CutData(data, cutexpression)[0]
        oBinaryFile.close()
        oOutput.Line('File: %s%s' % (filename, IFF(oBinaryFile.extracted, ' (extracted)', '')))
    else:
        data = content
        oOutput.Line('File: %s' % (filename))

    if options.hash:
        oOutput.Line('MD5   : %s' % hashlib.md5(data).hexdigest())
        oOutput.Line('SHA1  : %s' % hashlib.sha1(data).hexdigest())
        oOutput.Line('SHA256: %s' % hashlib.sha256(data).hexdigest())
    try:
        # ----- Put your data processing code here -----
        data, messages = TryExtractDecode(data)
        for message in messages:
            oOutput.Line(message)
        if data[0:2] == b'MZ' and not options.raw:
            extracted, messages = GetXorChainSection(data)
            if extracted != None:
                resultChain, dJSON = AnalyzeEmbeddedPEFileSub(extracted, options)
                if resultChain != [ERROR_NO_CONFIG]:
                    oOutput.JSON(dJSON)
                    for message in messages:
                        oOutput.Line(message)
                    for message in resultChain:
                        oOutput.Line(message)
                    FinalTests(extracted, options, oOutput)
                else:
                    extracted = None
            if extracted == None:
                error, sectiondata = GetDataSection(data)
                if error != None:
                    oOutput.Line('Error: PE file error: %s' % error)
                elif len(sectiondata) < 16:
                    oOutput.Line('Error: section .data too small: %d' % len(sectiondata))
                elif ProcessBinaryFileSub(sectiondata, data, oOutput, options):
                    pass
                else:
                    bytesToSkip = 0x20
                    oOutput.Line('Skipping %d bytes' % bytesToSkip)
                    ProcessBinaryFileSub(sectiondata[bytesToSkip:], data, oOutput, options)
            FinalTests(data, options, oOutput)
        elif TestShellcodeHeuristic(data):
            if IdentifyShellcode(data) == '':
                oOutput.Line('Probably found shellcode:')
            else:
                oOutput.Line('Found shellcode:')
            AnalyzeShellcode(data, oOutput)
            oOutput.Line(cDump(data).HexAsciiDump(rle=False))
            FinalTests(data, options, oOutput)
        else:
            dConfigs = {}
            if options.xorkeys:
                xorKeys = range(256)
            else:
                xorKeys = [0x2E, 0x69]
            for xorKey in xorKeys:
                xorKeyBytes = bytes([xorKey])
                startConfigXored = Xor(START_CONFIG, xorKeyBytes)
                for position in FindAll(data, startConfigXored):
                    result, dJSON = AnalyzeEmbeddedPEFileSub2(Xor(data[position:position+0x10000], xorKeyBytes), [], options)
                    configSha256 = hashlib.sha256(''.join(result).encode()).hexdigest()
                    if not configSha256 in dConfigs:
                        dConfigs[configSha256] = True
                        if result != [ERROR_SANITY_CHECK]:
                            oOutput.JSON(dJSON)
                            oOutput.Line('xorkey %s %02x' % (xorKeyBytes, xorKey))
                            for line in result:
                                oOutput.Line(line)
            if data[:4] == b'MDMP':
                try:
                    MinidumpFile
                except NameError:
                    print('minidump module is required for runtime config analysis: pip install minidump')
                else:
                    RuntimeAnalysis(data, dConfigs, oOutput, options)
            FinalTests(data, options, oOutput)
        # ----------------------------------------------
    except:
        oLogfile.LineError('Processing file %s %s' % (filename, repr(sys.exc_info()[1])))
        if not options.ignoreprocessingerrors:
            raise

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

def SpaceEvery2Characters(string):
    result = []
    while string != '':
        result.append(string[0:2])
        string = string[2:]
    return ' '.join(result)

def ProcessLicenseIDs(oOutput, oLogfile, options):
    rule_config = '''rule cs_%s_licenseid {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a
}
'''

    rule_config_i = '''rule cs_%s_licenseid_i {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a
}
'''

    rule_config_dot = '''rule cs_%s_licenseid_dot {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a
}
'''

    rule_shellcode = '''rule cs_%s_licenseid_shellcode {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a and filesize < 10000
}
'''

    rule_shellcode_00 = '''rule cs_%s_licenseid_shellcode_00 {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a and filesize < 10000
}
'''

    rule_shellcode_00_end = '''rule cs_%s_licenseid_shellcode_00_end {
  meta:
    license_name = "%s"
    license_id = "%d"
    info = "rule generated by 1768.py on %s"
  strings:
    $a = { %s }
  condition:
    $a and filesize < 10000 and $a at (filesize - 5)
}
'''

    for licenseid in options.licenseids.split(','):
        result = licenseid.split(':', 1)
        if len(result) == 1:
            idInteger = ParseInteger(licenseid)
            bytes = struct.pack('>I', idInteger)
            idName = binascii.b2a_hex(bytes).decode()
        else:
            idInteger = ParseInteger(result[1])
            bytes = struct.pack('>I', idInteger)
            idName = result[0]
        prefix = b'\x00\x25\x00\x02\x00\x04'
        oOutput.Line(rule_config % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(prefix + bytes).decode())))
        oOutput.Line(rule_config_i % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(Xor(prefix + bytes, b'i')).decode())))
        oOutput.Line(rule_config_dot % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(Xor(prefix + bytes, b'.')).decode())))
        oOutput.Line(rule_shellcode % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(bytes).decode())))
        oOutput.Line(rule_shellcode_00 % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(b'\x00' + bytes).decode())))
        oOutput.Line(rule_shellcode_00_end % (idName, idName, idInteger, FormatTime(), SpaceEvery2Characters(binascii.b2a_hex(b'\x00' + bytes).decode())))

class cOutputJSON(object):
    def __init__(self, oOutput, options):
        self.oOutput = oOutput
        self.options = options
        self.messages = []
        self.filename = ''
        self.JSONs = []

    def JSON(self, dJSON):
        self.JSONs.append(dJSON)

    def Line(self, line, eol='\n'):
        if self.options.jsonoutput:
            self.messages.append(line)
        else:
            self.oOutput.Line(line, eol)

    def Filename(self, filename, index, total):
        self.oOutput.Filename(filename, index, total)
        self.filename = filename

class cAPIOptions(object):
    def __init__(self):
        self.csv = False
        self.select = ''
        self.ignoreprocessingerrors = False
        self.raw = False
        self.verbose = False
        self.hash = False
        self.sanitycheck = False
        self.xorkeys = False

class cAPIOutput(object):
    def __init__(self):
        self.messages = []
        self.JSONs = []

    def JSON(self, dJSON):
        self.JSONs.append(dJSON)

    def Line(self, line):
        self.messages.append(line)

    def LineError(self, line):
        pass

def APIAnalyze(data, raw=False):
    oOutput = cAPIOutput()
    oOptions = cAPIOptions()
    if raw:
        oOptions.raw = True
    ProcessBinaryFile('', data, ':', '', oOutput, cAPIOutput(), oOptions)
    return oOutput.JSONs

def ProcessBinaryFiles(filenames, oLogfile, options):
    oOutput = cOutputJSON(InstantiateCOutput(options), options)
    index = 0
    if options.jsoninput:
        items = CheckJSON(sys.stdin.read())
        if items == None:
            return
        for item in items:
            oOutput.Filename(item['name'], index, len(items))
            index += 1
            ProcessBinaryFile(item['name'], item['content'], '', '', oOutput, oLogfile, options)
            if options.jsonoutput:
                oOutput.oOutput.Line(json.dumps({'filename': oOutput.filename, 'messages': oOutput.messages, 'config': oOutput.JSONs[0]}))
    elif options.licenseids != '':
        ProcessLicenseIDs(oOutput, oLogfile, options)
    else:
        for filename, cutexpression, flag in filenames:
            oOutput.Filename(filename, index, len(filenames))
            index += 1
            ProcessBinaryFile(filename, None, cutexpression, flag, oOutput, oLogfile, options)
            if options.jsonoutput:
                oOutput.oOutput.Line(json.dumps({'filename': oOutput.filename, 'messages': oOutput.messages, 'config': oOutput.JSONs[0]}))

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file|cut-expression|flag-expression ...]\n' + __description__ + moredesc, version='%prog ' + __version__, epilog='This tool also accepts flag arguments (#f#), read the man page (-m) for more info.')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-r', '--raw', action='store_true', default=False, help='Search through the file as a binary file, do not parse as a PE file')
    oParser.add_option('-s', '--select', default='', help='Field to select')
    oParser.add_option('-S', '--sanitycheck', action='store_true', default=False, help='Exclude configs that do not pass sanity check')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-l', '--licenseids', default='', help='License ID(s)/Watermark(s) to generate YARA rules for')
    oParser.add_option('-c', '--csv', action='store_true', default=False, help='Output config in CSV format')
    oParser.add_option('-p', '--password', default='infected', help='The ZIP password to be used (default infected)')
    oParser.add_option('-n', '--noextraction', action='store_true', default=False, help='Do not extract from archive file')
    oParser.add_option('-H', '--hash', action='store_true', default=False, help='Include hashes of file content')
    oParser.add_option('-x', '--xorkeys', action='store_true', default=False, help='Try all single byte XOR keys (not only 0x69 and 0x2e)')
    oParser.add_option('--literalfilenames', action='store_true', default=False, help='Do not interpret filenames')
    oParser.add_option('--recursedir', action='store_true', default=False, help='Recurse directories (wildcards and here files (@...) allowed)')
    oParser.add_option('--checkfilenames', action='store_true', default=False, help='Perform check if files exist prior to file processing')
    oParser.add_option('-j', '--jsoninput', action='store_true', default=False, help='Consume JSON from stdin')
    oParser.add_option('-J', '--jsonoutput', action='store_true', default=False, help='Output JSON')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='Verbose output')
    oParser.add_option('--logfile', type=str, default='', help='Create logfile with given keyword')
    oParser.add_option('--logcomment', type=str, default='', help='A string with comments to be included in the log file')
    oParser.add_option('--ignoreprocessingerrors', action='store_true', default=False, help='Ignore errors during file processing')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0 and options.jsoninput:
        print('Error: option -j can not be used with files')
        return

    oLogfile = cLogfile(options.logfile, options.logcomment)
    oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir, options.checkfilenames, '#c#', '#f#')
    oLogfile.Line('FilesCount', str(len(oExpandFilenameArguments.Filenames())))
    oLogfile.Line('Files', repr(oExpandFilenameArguments.Filenames()))
    if oExpandFilenameArguments.warning:
        PrintError('\nWarning:')
        PrintError(oExpandFilenameArguments.message)
        oLogfile.Line('Warning', repr(oExpandFilenameArguments.message))

    starttime = time.time()
    ProcessBinaryFiles(oExpandFilenameArguments.Filenames(), oLogfile, options)
    if options.verbose:
        print('Duration: %f' % (time.time() - starttime))

    if oLogfile.errors > 0:
        PrintError('Number of errors: %d' % oLogfile.errors)
    oLogfile.Close()

if __name__ == '__main__':
    Main()
