#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Text editor tool'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/07/03'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/06/18: start
  2021/06/28: refactor
  2021/07/03: update man

Todo:
  sarassign: avoid search & replace of matched regex
"""

import argparse
import csv
import re
import codecs
import textwrap

import time
import sys
import os

def PrintManual():
    manual = '''
Manual:

This is a tool that edits text files.

Text files are read as a whole (not line by line), hence very large text files that can not be read into memory, can not be processed.

The arguments to this tool are commands: each argument is a single command.
The syntax of a command has the following form: a=b,c=d,...
Where a and c are keys, and b and d the corresponding values.

You need to provide at least one command as argument. Commands are separated by space characters.

There are 3 different types of commands: input (input=file-in.txt), output (output=file-out.txt) and text editing (edit=...).

input=file-in.txt: with this command, the tool will read the provided text file (file-in.txt) into memory. Use - as filename to read from stdin.

output=file-out.txt: with this command, the tool will write the edited textfile to disk using the provided text file (file-out.txt). Use - as filename to write to stdout.

Text editing commands edit the text that was read with an input command.
There are 3 text editing commands:
sarcsv: perform a search and replace using a list of search and replace terms provided in a CSV file.
sar: perform a trivial search and replace.
sarassign: perform a search and replace using a regular expression to identify assignments.

Editing command sarcsv reads a CSV file, and uses each value in the first column as a search term, and each corresponding value in the second command is the replacement term.

For example, take text file example.txt with the following content:

  There is an apple on the sun.
  It is nice and warm.

And CSV file sar.csv with the following content:

  apple,pear
  sun,moon

The following sarcsv command edits file example.txt with sar.csv:

  ./texteditor.py input=example.txt edit=sarcsv,file=sar.csv output=-

The output of this command is:

  There is an pear on the moon.
  It is nice and warm.

Option file= provides the filename of the CSV file to use as input with search and replace terms.

If the CSV file starts with a header, use option header=y to skip this header.

The search and replacement terms present in the CSV file, can be modified prior to use using Python functions.

For example, to surround the replacement term with double quotes, you can use a Python lambda function like "lambda x: chr(0x22) + x + chr(0x22".
Like this:

  ./texteditor.py input=example.txt "edit=sarcsv,file=sar.csv,transformreplace=lambda x: chr(0x22) + x + chr(0x22)" output=-

This produces the following output:

  There is an "pear" on the "moon".
  It is nice and warm.

transformsearch is the option to use for a Python function on the search term, and transformreplace is the option to use for a Python function on the replace term.

Editing command sar performs a trivial search and replace.

Here is an example:

  ./texteditor.py input=example1.txt edit=sar,search=apple,replace=pear output=-

This produces the following output:

  There is an pear on the sun.
  It is nice and warm.

transformsearch and transformreplace can be used with edit command sar. Use value escape to indicate that a string contains escape characters:

Here is an example:

  ./texteditor.py input=example1.txt edit=sar,search=apple,replace=\x22pear\x22,transformreplace=escape output=-

This produces the following output:

  There is an "pear" on the sun.
  It is nice and warm.

Editing command sarassign performs a search and replace for assignments of values. A regular expression is used to find assignments.

For example, take text file example.txt with the following content:

  Let variable = 20
  Print "Value: " & variable

What we want to achieve here, is replace variable with 20, by matching assignment "Let variable = 20".

Use regex to spicify the command: regex=Let (?P<s>[a-z]+) = (?P<r>.+)

(?P<s>) is a named capturing group with name s: this is the searchterm.
(?P<r>) is a named capturing group with name r: this is the replaceterm.

This can be done with the following command:

  ./texteditor.py input=example.txt "edit=sarassign,regex=Let (?P<s>[a-z]+) = (?P<r>.+)" output=-

This produces the following output:

  Let 20 = 20
  Print "Value: " & 20

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

TE_COMMAND = 'edit'
TE_COMMAND_SARCSV = 'sarcsv'
TE_COMMAND_SAR = 'sar'
TE_COMMAND_SARASSIGN = 'sarassign'
TE_HEADER = 'header'
TE_SEARCH = 'search'
TE_REPLACE = 'replace'
TE_TRANSFORMSEARCH = 'transformsearch'
TE_TRANSFORMREPLACE = 'transformreplace'
TE_ESCAPE = 'escape'
TE_FILE = 'file'
TE_REGEX = 'regex'
TE_INPUT = 'input'
TE_OUTPUT = 'output'

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

ESCAPE_SEQUENCE_RE = re.compile(r'''
    ( \\U........      # 8-digit hex escapes
    | \\u....          # 4-digit hex escapes
    | \\x..            # 2-digit hex escapes
    | \\[0-7]{1,3}     # Octal escapes
    | \\N\{[^}]+\}     # Unicode characters by name
    | \\[\\'"abfnrtv]  # Single-character escapes
    )''', re.UNICODE | re.VERBOSE)

def DecodeEscapes(str):
    def DecodeMatch(match):
        return codecs.decode(match.group(0), 'unicode-escape')

    return ESCAPE_SEQUENCE_RE.sub(DecodeMatch, str)

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

def ParseSplit(command):
    separator = ','
    letters = 'abcdefghijklmnopqrstuvwxyz'
    equal = '='
    positionSeparators = []
    positionLastSeparator = -1
    for position, character in enumerate(command):
        if character == separator:
            if positionLastSeparator != -1:
                positionSeparators.append(positionLastSeparator)
                positionLastSeparator = -1
            else:
                positionLastSeparator = position
        elif character == equal:
            if positionLastSeparator != -1:
                positionSeparators.append(positionLastSeparator)
                positionLastSeparator = -1
        elif not character.lower() in letters:
            if positionLastSeparator != -1:
                positionLastSeparator = -1
    positionSeparators = [-1] + positionSeparators + [len(command)]
    result = []
    while len(positionSeparators) > 1:
        result.append(command[positionSeparators[0] + 1:positionSeparators[1]])
        positionSeparators = positionSeparators[1:]
    return result

def ParseCommand(command):
    dCommand = {}
    for element in ParseSplit(command):
        name, value = element.split('=', 1)
        name = name.lower().strip()
        dCommand[name] = value
    return dCommand

def SearchAndReplace(args):
    sartext = ''
    for command in args.commands:
        dCommand = ParseCommand(command)
        if TE_COMMAND in dCommand:
            if dCommand[TE_COMMAND] == TE_COMMAND_SARCSV:
                skipHeader = dCommand.get(TE_HEADER, 'n').lower() == 'y'
                searchTermFunction = eval(dCommand.get(TE_TRANSFORMSEARCH, 'lambda x: x'))
                replaceTermFunction = eval(dCommand.get(TE_TRANSFORMREPLACE, 'lambda x: x'))
                for row in csv.reader(open(dCommand[TE_FILE])):
                    if skipHeader:
                        skipHeader = False
                        continue
                    searchterm = searchTermFunction(row[0])
                    replaceterm = replaceTermFunction(row[1])
                    sartext = sartext.replace(searchterm, replaceterm)
            elif dCommand[TE_COMMAND] == TE_COMMAND_SAR:
                searchterm = dCommand.get(TE_SEARCH, '')
                replaceterm = dCommand.get(TE_REPLACE, '')
                searchTermTransform = dCommand.get(TE_TRANSFORMSEARCH, '')
                if searchTermTransform == TE_ESCAPE:
                    searchterm = DecodeEscapes(searchterm)
                replaceTermTransform = dCommand.get(TE_TRANSFORMREPLACE, '')
                if replaceTermTransform == TE_ESCAPE:
                    replaceterm = DecodeEscapes(replaceterm)
                sartext = sartext.replace(searchterm, replaceterm)
            elif dCommand[TE_COMMAND] == TE_COMMAND_SARASSIGN:
                oRE = re.compile(dCommand[TE_REGEX])
                for oMatch in oRE.finditer(sartext):
                    searchterm = oMatch.groupdict()['s']
                    replaceterm = oMatch.groupdict()['r']
                    sartext = sartext.replace(searchterm, replaceterm)
        else:
            if TE_INPUT in dCommand:
                if dCommand['input'] == '-':
                    sartext = sys.stdin.read()
                else:
                    with open(dCommand['input'], 'r') as fIn:
                        sartext = fIn.read()
            elif TE_OUTPUT in dCommand:
                if dCommand['output'] == '-':
                    print(sartext, end='')
                else:
                    with open(dCommand['output'], 'w') as fIn:
                        fIn.write(sartext)

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oArgumentParser = argparse.ArgumentParser(description=__description__ + moredesc)
    oArgumentParser.add_argument('-m', '--man', action='store_true', default=False, help='Print manual')
    oArgumentParser.add_argument('--version', action='version', version=__version__)
    oArgumentParser.add_argument('commands', nargs='*', help='commands to process')
    args = oArgumentParser.parse_args()

    if args.man:
        oArgumentParser.print_help()
        PrintManual()
        return

    if len(args.commands) == 0:
        print('Please provide a command!')
        return

    SearchAndReplace(args)

if __name__ == '__main__':
    Main()
