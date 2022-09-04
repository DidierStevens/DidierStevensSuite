#!/usr/bin/env python

__description__ = 'VBA declare/createobject plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2022/07/21'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/10/25: start
  2015/11/04: added keywords
  2019/11/25: 0.0.3 update for GetObject, Callbyname and Shell
  2022/07/21: 0.0.4 added generalization
  2022/09/04: 0.0.5 improved generalization and added option -p

Todo:
"""

import re

#https://github.com/decalage2/oletools/blob/f2cbbbaea5e8a809360ab338bd54ae281e4fd54f/oletools/olevba.py
RESERVED_KEYWORDS = ['AutoExec', 'AutoOpen', 'DocumentOpen', 'AutoExit', 'AutoClose', 'Document_Close', 'DocumentBeforeClose', 'DocumentChange', 'AutoNew', 'Document_New', 'NewDocument', 'Document_Open', 'Document_BeforeClose', 'Auto_Open', 'Workbook_Open', 'Workbook_Activate', 'Auto_Ope', 'Auto_Close', 'Workbook_Close', 'Workbook_BeforeClose', 'Worksheet_Calculate']

def IsReservedKeyword(keyword):
    return keyword.lower() in [reserved.lower() for reserved in RESERVED_KEYWORDS]

def ContainsString(stringsToFind, containingString):
    containingString = containingString.lower()
    for stringToFind in stringsToFind:
        if stringToFind.lower() in containingString:
            return True
    return False
            
def ExtractDeclareFunctionSub(line):
    if ContainsString(['declare'], line):
        oMatch = re.search(r'(function|sub)\s+(\S+)\s+', line, re.I)
        if oMatch == None:
            return None
        keyword = oMatch.group(2)
        oMatch = re.search(r'\s+alias\s+"([^"]+)"', line, re.I)
        if oMatch == None:
            return keyword, None
        else:
            return keyword, oMatch.group(1)
    else:
        return None, None

def ExtractSetObjectVariable(line):
    if ContainsString(['createobject', 'getobject'], line):
        oMatch = re.search(r'(\S+)\s*=\s*(CreateObject|GetObject)', line, re.I)
        if oMatch == None:
            return None
        return oMatch.group(1)
    else:
        return None

def SpecialTrim(input):
    unwanteds = ['(', ',']
    for unwanted in unwanteds:
        position = input.find(unwanted)
        if position == -1:
            continue
        input = input[:position]
    return input

def ExtractDimVariable(line):
    if ContainsString(['dim'], line):
        oMatch = re.search(r'\s*Dim\s+(\S+)', line, re.I)
        if oMatch == None:
            return None
        variableName = SpecialTrim(oMatch.group(1))
        return variableName
    else:
        return None

def ExtractSubVariable(line):
    if ContainsString(['sub', 'function'], line):
        oMatch = re.search(r'\s*(sub|function)\s+(\S+)', line, re.I)
        if oMatch == None:
            return []
        result = [oMatch.group(2).split('(')[0]]
        if not '(' in line:
            return result
        arguments = line.split('(')[1]
        if not ')' in arguments:
            return result
        arguments = arguments.split(')')[0]
        for argument in arguments.split(','):
            argument = argument.strip()
            if argument.lower().startswith('byref ') or argument.lower().startswith('byval '):
                argument = argument[6:] 
            oMatch = re.search(r'\s*(\S+)', argument, re.I)
            if oMatch != None:
                result.append(oMatch.group(1))
        return result
    else:
        return []

def ExtractVariableEqual(line):
    if ContainsString(['='], line):
        oMatch = re.search(r'\s*(\S+)\s*=', line, re.I)
        if oMatch == None:
            return None
        variableName = SpecialTrim(oMatch.group(1))
        return variableName
    else:
        return None

def ExtractMoreVariables(line):
    result = ExtractDimVariable(line)
    if result != None:
        return [result]
    result = ExtractSubVariable(line)
    if result != []:
        return result
    result = ExtractVariableEqual(line)
    if result != None:
        return [result]
    return []

def ReplaceOutsideStrings(line, search, replace):
    # add code to handle "" inside string
    result = []
    outsideString = ''
    insideString = ''
    for character in line:
        if outsideString == '':
            if character == '"':
                outsideString += character
                result.append(insideString)
                insideString = ''
            else:
                insideString += character
        else:
            if character == '"':
                outsideString += character
                result.append(outsideString)
                outsideString = ''
            else:
                outsideString += character
    if insideString != '':
        result.append(insideString)
    if outsideString != '':
        result.append(outsideString)

    newline = ''
    for index, value in enumerate(result):
        if index % 2 == 0:
            value = re.sub(r'\b%s\b' % search, replace, value)
        newline += value
    return newline

class cVBADCO(cPluginParent):
    macroOnly = True
    name = 'VBA DCO (Declare/CreateObject) plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        oParser = optparse.OptionParser()
        oParser.add_option('-g', '--generalize', action='store_true', default=False, help='Generalize identifiers')
        oParser.add_option('-a', '--all', action='store_true', default=False, help='Output all lines when option -g is used')
        oParser.add_option('-p', '--predefine', default='', help='Predefine identifiers')
        (options, args) = oParser.parse_args(self.options.split(' '))

        self.ran = True

        dAliases = {}
        dPredefinitions = {}
        for predefinition in options.predefine.split(','):
            if predefinition == '':
                continue
            key, value = predefinition.split(':', 1)
            dPredefinitions[int(key)] = value

        oREDCO = re.compile(r'\b(declare|createobject|getobject|callbyname|shell)\b', re.I)
        result = [line.strip() for line in self.stream.split('\n') if re.search(oREDCO, line) != None]
        keywords = []
        for line in result:
            keyword, alias = ExtractDeclareFunctionSub(line)
            if keyword != None and not keyword in keywords and not IsReservedKeyword(keyword):
                keywords.append(keyword)
            if alias != None:
                dAliases[keyword] = alias
            keyword = ExtractSetObjectVariable(line)
            if keyword != None and not keyword in keywords and not IsReservedKeyword(keyword):
                keywords.append(keyword)
        keywordLines = [line.strip() for line in self.stream.split('\n') if ContainsString(keywords, line)]
        if keywordLines != []:
            result.append('-' * 80)
            result.extend(keywordLines)

        if not options.generalize:
            return result

        dKeywords = {}
        for index, keyword in enumerate(keywords):
            index = index + 1
            if keyword in dAliases:
                dKeywords[keyword] = dAliases[keyword]
            else:
                dKeywords[keyword] = dPredefinitions.get(index, 'Identifier%04d' % (index))
        for line in self.stream.split('\n'):
            for variable in ExtractMoreVariables(line):
                if not variable in dKeywords and not IsReservedKeyword(variable):
                    index = len(dKeywords) + 1
                    dKeywords[variable] = dPredefinitions.get(index, 'Identifier%04d' % (index))
                
        if options.all:
            toprocess = self.stream.split('\n')
        else:
            toprocess = result
        result = []
        for line in toprocess:
            for key, value in sorted(dKeywords.items(), key=lambda x: len(x[0]), reverse=True):
                line = ReplaceOutsideStrings(line, key, value)
            result.append(line)
        return result

AddPlugin(cVBADCO)
