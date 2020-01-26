#!/usr/bin/env python

__description__ = 'VBA parsing plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/09/17'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

options:
  -v                  print variable names
  -d var=value        define variable, example: -d ATTH=http
  -u value            define all unknown variables to the same value, example: -u http

History:
  2015/07/15: start
  2015/07/22: detecting obfuscated http: if 'http' in ''.join([c for c in expressionValue.lower() if c.isalpha()])
  2015/08/11: added method calls
  2015/08/18: added stream_joined (for statements split over lines terminated with _)
  2015/08/26: fixed ReplChrFunction regex
  2015/09/04: added option -d
  2015/09/17: added option -u

Todo:
  This is a quick and dirty hack, to be replaced with a BNF parser
"""

import re

def RemoveLeadingWhitespaceAndLineComment(expression):
    expression = expression.lstrip()
    if len(expression) > 0 and expression[0] == "'":
        return ''
    else:
        return expression

def MatchString(expression):
    expression = RemoveLeadingWhitespaceAndLineComment(expression)
    if len(expression) > 0 and expression[0] != '"':
        return None, expression
    else:
        rest = expression[1:]
        position = rest.find('"')
        if position == -1:
            return None, expression
        else:
            return rest[0:position], RemoveLeadingWhitespaceAndLineComment(rest[position + 1:])

def MatchVariable(expression):
    expression = RemoveLeadingWhitespaceAndLineComment(expression)
    if len(expression) > 0 and not expression[0].isalpha():
        return None, expression
    else:
        characters = [c for c in expression]
        variable = ''
        while len(characters) > 0 and (characters[0].isalnum() or characters[0] == '_'):
            variable += characters[0]
            characters = characters[1:]
        return variable, RemoveLeadingWhitespaceAndLineComment(''.join(characters))

def ReplChrFunction(oMatch):
    if re.match(r'^[ 0-9()/*+^-]+$', oMatch.group(1)):
        return '"' + chr(eval(oMatch.group(1))) + '"'
    else:
        return oMatch.group(0)
    
def EvaluateChrFunction(expression):
    return re.sub(r'chrw?\$?\s*\(([^)]+)\)', ReplChrFunction, expression, flags=re.I)

def MatchExpression(expression, dVariables):
    expression = EvaluateChrFunction(expression)
    resultString, restExpression = MatchString(expression)
    if resultString == None:
        variable, restExpression = MatchVariable(expression)
        if variable == None or not variable in dVariables:
            return None
        resultString = dVariables[variable]
    if resultString == None:
        return None
    elif restExpression == '':
        return resultString
    elif len(restExpression) > 0 and restExpression[0] in ('+', '&'):
        restResult = MatchExpression(restExpression[1:], dVariables)
        if restResult == None:
            return None
        return resultString + restResult
    else:
        return None

class cVBA(cPluginParent):
    macroOnly = True
    name = 'VBA parsing plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.stream_joined = stream.replace('_\x0D\x0A', '')
        self.options = options
        self.ran = False

    def ParseVariableDefinitions(self, definitions):
        position = definitions.find('=')
        if position == -1:
            return
        self.dVariables[definitions[0:position].strip()] = definitions[position+1:]
        
    def Analyze(self):
        self.ran = True
        self.dVariables = {}
        self.result = []

        if self.options.startswith('-d'):
            self.ParseVariableDefinitions(self.options[2:])
        	
        # parse assigments
        for oMatch in re.findall(r'^\s*([a-z0-9_]+)\s*=\s*(.+)\s*$', self.stream_joined, re.I + re.M):
            expressionValue = MatchExpression(oMatch[1].strip(), self.dVariables)
            if expressionValue != None:
                if 'http' in ''.join([c for c in expressionValue.lower() if c.isalpha()]):
                    if self.options == '-v':
                        self.result.append(oMatch[0] + ': ' + expressionValue)
                    else:
                        self.result.append(expressionValue)
                self.dVariables[oMatch[0]] = expressionValue
            elif self.options.startswith('-u'):
                self.dVariables[oMatch[0]] = self.options[3:]
        # parse method calls
        for oMatch in re.findall(r'^\s*[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?[ \t]+([^,\n]+([ \t]*,[ \t]*[^,\n]+)*)$', self.stream_joined, re.I + re.M):
            for expression in oMatch[1].split(','):
                expressionValue = MatchExpression(expression.strip(), self.dVariables)
                if expressionValue != None:
                    if 'http' in ''.join([c for c in expressionValue.lower() if c.isalpha()]):
                        self.result.append(expressionValue)
        return self.result

AddPlugin(cVBA)
