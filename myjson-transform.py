#!/usr/bin/env python

from __future__ import print_function

__description__ = 'myjson-transform'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2023/03/28'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2023/03/25: start
  2023/03/28: continue

Todo:
"""

import optparse
import sys
import binascii
import json
import re
import textwrap
import os
from io import StringIO

def PrintManual():
    manual = r'''
Manual:

This tool takes JSON output from tools like oledump, zipdump, base64dump, ... via stdin and transforms the data produced by these tools.
The transformation function (name Transform) has to be defined in a Python script provided via option -s.

This Transform function has 2 arguments: items and options.
items is a list of dictionaries produced by the "feeding" tool , e.g., the tool whose JSON output is piped into this tool (oledump, ...).
Each dictionary has 3 keys: id, name and content.

The transformation function reads content from the items, and transforms it. The transformed data is the return value of the Transform function, and it can also be stored in the items list (modifying the values of the dictionaries, like the content value for example).

By default, this tool will output the transformed data (return value of Transform function) as binary data.
With options -a, -A, -x, -X, -b, -B this output can be presented as ASCII dump, hex dump and base64 dump. Option -d is also present to explicitly request a binary dump.

If option --jsonoutput is used, then the return value of the Transform function is ignored, and in stead, the transformed items are output as JSON data.
The --jsonouput option can not be combined with the above output format options.

Option -p (--parameter) is a string option that is passed on to the Transform function (via options argument). It is designed to be used by the developer of the Transform function as they see fit.
For example, it can be used to tell the Transform function which item to select for transformation, in case there are several items.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def GetDumpOption(options, default=None):
    dPossibleOptions = {
        'asciidump': 'a',
        'hexdump': 'x',
        'dump': 'd',
        'asciidumprle': 'A',
        'hexdumpnows': 'X',
        'base64': 'b',
        'base64nows': 'B',
    }

    for attribute, option in dPossibleOptions.items():
        if hasattr(options, attribute) and getattr(options, attribute):
            return option
    return default

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
        encoded = binascii.b2a_base64(self.data).decode().strip()
        if nowhitespace:
            return encoded
        oDumpStream = self.cDumpStream(self.prefix)
        length = 64
        for i in range(0, len(encoded), length):
            oDumpStream.Addline(encoded[0+i:length+i])
        return oDumpStream.Content()

    def HexDumpNoWS(self):
        return self.data.hex()

    def DumpOption(self, option):
        if option == 'a':
            return self.HexAsciiDump()
        elif option == 'A':
            return self.HexAsciiDump(rle=True)
        elif option == 'x':
            return self.HexDump()
        elif option == 'X':
            return self.HexDumpNoWS()
        elif option == 'b':
            return self.Base64Dump()
        elif option == 'B':
            return self.Base64Dump(nowhitespace=True)
        else:
            raise Exception('DumpOption: unknown option %' % option)

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

def ProduceJSON(items):
    for item in items:
        item['content'] = binascii.b2a_base64(item['content']).decode().strip('\n')

    return json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': items})

def MyJSONTransform(options):
    items = CheckJSON(sys.stdin.read())
    transformed = Transform(items, options)
    if options.jsonoutput:
        print(ProduceJSON(items))
    else:
        dumpoption = GetDumpOption(options, 'd')
        if dumpoption == 'd':
            sys.stdout.buffer.write(transformed)
        else:
            print(cDump(transformed).DumpOption(dumpoption), end='')

def LoadScriptIfExists(filename):
    if os.path.exists(filename):
        exec(open(filename, 'r').read(), globals(), globals())

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__, epilog='This tool also accepts flag arguments (#f#), read the man page (-m) for more info.')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--script', type=str, default='', help='Script with definitions to include')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='Produce JSON output')
    oParser.add_option('-p', '--parameter', type=str, default='', help='Parameter for the script')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-X', '--hexdumpnows', action='store_true', default=False, help='perform hex dump without whitespace')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-b', '--base64', action='store_true', default=False, help='perform BASE64 dump')
    oParser.add_option('-B', '--base64nows', action='store_true', default=False, help='perform BASE64 dump without whitespace')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0:
        print('Error: this tool expects input from stdin')
        return

    if options.script != '':
        LoadScriptIfExists(options.script)

    MyJSONTransform(options)

if __name__ == '__main__':
    Main()
