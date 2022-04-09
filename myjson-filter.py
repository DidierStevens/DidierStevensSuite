#!/usr/bin/env python

from __future__ import print_function

__description__ = 'myjson-filter'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2022/04/09'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/03/28: start
  2022/04/04: continue
  2022/04/09: added option -l

Todo:
"""

import optparse
import sys
import binascii
import json
import re
import textwrap

def PrintManual():
    manual = r'''
Manual:

This tool takes JSON output from tools like oledump, zipdump, ... via stdin, filters the items, and outputs JSON to stdout.

Option -n (--namefilter) can be used to file items based on their names. The value for option -n is a regular expression to select matching names.

Option -c (--contentfilter) can be used to file items based on their content. The value for option -c is a regular expression to select matching content.

Flags can be added to regular expressions as follows: #flags#regex.
Flags can be i (ignore case) and v (reverse selection).

Use option -l to list the selected items, in stead of outputing JSON data.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def PrintError(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

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

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

def ParseHashOption(value):
    result, remainder = StartsWithGetRemainder(value, '#')
    if not result:
        return '', value
    position = remainder.find('#')
    if position == -1:
        return '', value
    return remainder[:position], remainder[position + 1:]

def ParseHashFilter(value):
    flagsRE = 0
    flagReverse = False
    flags, filterExpression = ParseHashOption(value)
    for flag in flags:
        if flag == 'i':
            flagsRE = re.I
        elif flag == 'v':
            flagReverse = True
        else:
            raise Exception('Unknown flag: %s for option %s' % (flag, value))       
    return filterExpression, flagsRE, flagReverse

def MyJSONFilter(options):
    items = CheckJSON(sys.stdin.read())

    if items == None:
        return

    if options.namefilter != '':
        filterExpression, flagsRE, flagReverse = ParseHashFilter(options.namefilter)
        oRE = re.compile(filterExpression, flagsRE)
        selectedItems = []
        for item in items:
            if oRE.search(item['name']):
                if not flagReverse:
                    selectedItems.append(item)
            elif flagReverse:
                selectedItems.append(item)
        items = selectedItems

    if options.contentfilter != '':
        filterExpression, flagsRE, flagReverse = ParseHashFilter(options.contentfilter)
        oRE = re.compile(filterExpression.encode(), flagsRE)
        selectedItems = []
        for item in items:
            if oRE.search(item['content']):
                if not flagReverse:
                    selectedItems.append(item)
            elif flagReverse:
                selectedItems.append(item)
        items = selectedItems

    for item in items:
        item['content'] = binascii.b2a_base64(item['content']).decode().strip('\n')

    if options.list:
        for item in items:
            print('%3d: %s' % (item['id'], item['name']))
    else:
        print(json.dumps({'version': 2, 'id': 'didierstevens.com', 'type': 'content', 'fields': ['id', 'name', 'content'], 'items': items}))

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__, epilog='This tool also accepts flag arguments (#f#), read the man page (-m) for more info.')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-n', '--namefilter', type=str, default='', help='Regular expression to filter for the item name')
    oParser.add_option('-c', '--contentfilter', type=str, default='', help='Regular expression to filter for the content')
    oParser.add_option('-l', '--list', action='store_true', default=False, help='List selected items')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 0:
        print('Error: this tool expects input from stdin')
        return

    MyJSONFilter(options)

if __name__ == '__main__':
    Main()
