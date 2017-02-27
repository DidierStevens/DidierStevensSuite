#!/usr/bin/env python

__description__ = "Program to analyze password history"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/02/27'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/08/12: start
  2017/02/05: cleanup, refactoring
  2017/02/07: fixed output, added percentage and option -s
  2017/02/08: fixed output, added options -l and -n
  2017/02/10: updated man
  2017/02/13: added LongestCommonString
  2017/02/27: added option -L

Todo:
"""

import optparse
import glob
import collections
import re
import sys
import textwrap

def PrintManual():
    manual = '''
Manual:

This program analyzes files with password history, and reports statistics on common strings (prefix, suffix, infix) of passwords per user.
The minimum lenght of a common string is 3 characters by default. Use option -L to change the minimum length of the common string.


Example of input file (passwords.txt):
user01:HASH:azerty-
user01_history0:HASH:azerty0
user01_history1:HASH:azerty1
user01_history2:HASH:azerty2
user01_history3:HASH:azerty3
user01_history4:HASH:azerty4
user01_history5:HASH:azerty5
user01_history6:HASH:azerty6
user01_history7:HASH:azerty7
user01_history8:HASH:azerty8
user01_history9:HASH:azerty9
user01_history10:HASH:azerty10
user01_history11:HASH:azerty11
user01_history12:HASH:azerty12
user01_history13:HASH:azerty13
user01_history14:HASH:azerty14
user01_history15:HASH:azerty15
user01_history16:HASH:azerty16
user01_history17:HASH:azerty17
user01_history18:HASH:azerty18
user01_history19:HASH:azerty19
user01_history20:HASH:azerty20
user01_history21:HASH:azerty21
user01_history22:HASH:azerty22
user02:HASH:99Monkey
user02_history0:HASH:00Monkey
user02_history1:HASH:01Monkey
user02_history2:HASH:02Monkey
user02_history3:HASH:03Monkey
user02_history4:HASH:04Monkey
user02_history5:HASH:05Monkey
user02_history6:HASH:06Monkey
user02_history7:HASH:07Monkey
user02_history8:HASH:08Monkey
user02_history9:HASH:09Monkey
user02_history10:HASH:10Monkey
user02_history11:HASH:11Monkey
user02_history12:HASH:12Monkey
user02_history13:HASH:13Monkey
user02_history14:HASH:14Monkey
user02_history15:HASH:15Monkey
user02_history16:HASH:16Monkey
user02_history17:HASH:17Monkey
user02_history18:HASH:18Monkey
user02_history19:HASH:19Monkey
user02_history20:HASH:20Monkey
user02_history21:HASH:21Monkey
user02_history22:HASH:22Monkey
user03:HASH:SomethingElse
user03_history0:HASH:Password0
user03_history1:HASH:Password1
user03_history2:HASH:Password2
user03_history3:HASH:Password3
user03_history4:HASH:Password4
user03_history5:HASH:Password5
user03_history6:HASH:Password6
user03_history7:HASH:Password7
user03_history8:HASH:Password8
user03_history9:HASH:Password9
user03_history10:HASH:Password10
user03_history11:HASH:Azerty$1

Usage example:
password-history-analysis.py passwords.txt

Output:
user01:24:24:100.00:azerty
user02:24:24:100.00:Monkey
user03:13:11:84.62:Password

The first field is the username.
The second field is the number of passwords for the given username.
The third field is the largest number of passwords for the given username with the same prefix or suffix.
The fourth field is the percentage of third and second field.
The fifth field is the password's common string.

The report can be written to file with option -o.
Use option -l to convert usernames to lowercase.

Option -n will not produce a report, but output all lines that do not match a password entry. Use this to detect entries not handled by this program.

The separator (for input and output) is :, and can be changed with option -s.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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

class cOutput():
    def __init__(self, filename=None):
        self.filename = filename
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if self.f:
            self.f.write(line + '\n')
        else:
            print(line)

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

class cOutputResult():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options

    def Line(self, line):
        self.oOutput.Line(line)

    def Close(self):
        self.oOutput.Close()

def ProcessFile(fIn, fullread):
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n')

def ComparePasswordsLeftToRight(password1, password2):
    common = ''
    for i in range(0, min(len(password1), len(password2))):
        if password1[i] == password2[i]:
            common += password1[i]
        else:
            return common
    return common

def ComparePasswordsRightToLeft(password1, password2):
    return ComparePasswordsLeftToRight(password1[::-1], password2[::-1])[::-1]

def AnalyzePasswordsPrefixSuffix(passwords, minimumlength):
    commons = {}
    for i in range(0, len(passwords) - 1):
        for j in range(i + 1, len(passwords)):
            common = ComparePasswordsLeftToRight(passwords[i], passwords[j])
            if len(common) >= minimumlength:
                if not common in commons:
                    commons[common] = 0
                commons[common] += 1
            common = ComparePasswordsRightToLeft(passwords[i], passwords[j])
            if len(common) >= minimumlength:
                if not common in commons:
                    commons[common] = 0
                commons[common] += 1
    return commons

def LongestCommonString(string1, string2):
    dMatrix = {}
    longest = 0
    result = []
    for i in range(len(string1)):
        for j in range(len(string2)):
            if string1[i] == string2[j]:
                if i == 0 or j == 0:
                    dMatrix[i,j] = 1
                else:
                    dMatrix[i,j] = dMatrix[i-1,j-1] + 1
                if dMatrix[i,j] > longest:
                    longest = dMatrix[i,j]
                    result = [string1[i-longest+1:i+1]]
                elif dMatrix[i,j] == longest:
                    result = result + [string1[i-longest+1:i+1]]
            else :
                dMatrix[i,j] = 0
    if len(result) > 0:
        return result[0]
    else:
        return ''

def AnalyzePasswordsLongestCommonString(passwords, minimumlength):
    commons = {}
    for i in range(0, len(passwords) - 1):
        for j in range(i + 1, len(passwords)):
            common = LongestCommonString(passwords[i], passwords[j])
            if len(common) >= minimumlength:
                if not common in commons:
                    commons[common] = 0
                commons[common] += 1
    return commons

def PasswordHistoryAnalysisSingle(filenames, oOutput, options):
    oRE = re.compile(options.separator.join(['^([^', ']+)', '([^', ']+)', '(.+)$']))
    oREHistory = re.compile('^(.+)_history\d+$')
    for filename in filenames:
        dUsernames = {}
        if filename == '':
            fIn = sys.stdin
        else:
            fIn = open(filename, 'r')
        for line in ProcessFile(fIn, False):
            results = oRE.match(line)
            if results != None:
                oMatchHistory = oREHistory.match(results.groups()[0])
                if oMatchHistory != None:
                    username = oMatchHistory.groups()[0]
                else:
                    username = results.groups()[0]
                if options.lowercase:
                    username = username.lower()
                if not username in dUsernames:
                    dUsernames[username] = []
                dUsernames[username].append(results.groups()[2])
            elif options.nonmatching:
                oOutput.Line(line)
        if fIn != sys.stdin:
            fIn.close()
        if not options.nonmatching:
            for username, passwords in sorted(dUsernames.items()):
                commons = sorted([(value, key) for key, value in AnalyzePasswordsPrefixSuffix(passwords, options.length).items()])
                if len(commons) == 0:
                    commons = sorted([(value, key) for key, value in AnalyzePasswordsLongestCommonString(passwords, options.length).items()])
                if len(commons) > 0:
                    counter = 0
                    for password in passwords:
                        if commons[-1][1] in password:
                            counter += 1
                    oOutput.Line(options.separator.join(['%s', '%d', '%d', '%0.2f', '%s']) % (username, len(passwords), counter, float(counter) / float(len(passwords)) * 100.0, commons[-1][1]))
                else:
                    oOutput.Line(options.separator.join(['%s', '%d', '%d', '%0.2f', '%s']) % (username, len(passwords), 0, 0.0, ''))

def PasswordHistoryAnalysis(filenames, options):
    oOutput = cOutputResult(options)
    PasswordHistoryAnalysisSingle(filenames, oOutput, options)
    oOutput.Close()

def Main():
    global dLibrary

    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-s', '--separator', type=str, default=':', help='Separator used in the password files (default :)')
    oParser.add_option('-l', '--lowercase', action='store_true', default=False, help='Convert usernames to lowercase')
    oParser.add_option('-n', '--nonmatching', action='store_true', default=False, help='Print lines that do not match a password entry')
    oParser.add_option('-L', '--length', type=int, default=3, help='Minimum length common string')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) == 0:
        oParser.print_help()
    else:
        PasswordHistoryAnalysis(ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
