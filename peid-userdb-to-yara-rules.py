#!/usr/bin/env python

__description__ = 'Convert PeID userdb to YARA rules'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2015/02/15'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/09: start
  2015/01/20: continue
  2015/01/21: added man
  2015/02/15: 0.0.2: added value of option --exclude to generated rules file

Todo:
"""

import optparse
import re
import binascii
import time
import textwrap

def PrintManual():
    manual = '''
Manual:

This program converts PEiD signatures to YARA rules. These signatures are typically found in file userdb.txt. Since PEiD signature names don't need to be unique, and can contain characters that are not allowed in YARA rules, the name of the YARA rule is prefixed with PEiD_ and a running counter, and non-alphanumeric characters are converted to underscores (_).
Signatures that can not be parsed are ignored.

Here is an example:
PEiD signature:

 [!EP (ExE Pack) V1.0 -> Elite Coding Group]
 signature = 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10
 ep_only = true

Generated YARA rule:
 
 rule PEiD_00001__EP__ExE_Pack__V1_0____Elite_Coding_Group_
 {
     meta:
         description = "[!EP (ExE Pack) V1.0 -> Elite Coding Group]"
         ep_only = "true"
     strings:
         $a = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10}
     condition:
         $a
 }

PEiD signatures have an ep_only property that can be true or false. This property specifies if the signature has to be found at the PE file's entry point (true) or can be found anywhere (false).
This program will convert all signatures, regardless of the value of the ep_only property. Use option -e to convert only rules with ep_only property equal to true or false.

Option -p generates rules that use YARA's pe module. If a signature has ep_only property equal to true, then the YARA rule's condition becomes $a at pe.entry_point instead of just $a.

Example:

 import "pe"

 rule PEiD_00001__EP__ExE_Pack__V1_0____Elite_Coding_Group_
 {
     meta:
         description = "[!EP (ExE Pack) V1.0 -> Elite Coding Group]"
         ep_only = "true"
     strings:
         $a = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10}
     condition:
         $a at pe.entry_point
 }

Specific signatures can be excluded with option -x. This option takes a file that contains signatures to ignore (signatures like 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10, not names like [!EP (ExE Pack) V1.0 -> Elite Coding Group]).
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

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
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

counter = 0

def ConvertRuleName(name):
    global counter

    counter += 1
    return ('PEiD_%05d' % counter) + ''.join([IFF(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_', c, '_') for c in name])

def PEiDUserdbRuleToYARARule(rule, pe):
    if pe and rule[3] == "true":
        return """rule %s
{
    meta:
        description = "%s"
        ep_only = "%s"
    strings:
        $a = {%s}
    condition:
        $a at pe.entry_point
}
""" % (ConvertRuleName(rule[0]), rule[0].replace('"', '\\"'), rule[3], rule[1])
    else:
        return """rule %s
{
    meta:
        description = "%s"
        ep_only = "%s"
    strings:
        $a = {%s}
    condition:
        $a
}
""" % (ConvertRuleName(rule[0]), rule[0].replace('"', '\\"'), rule[3], rule[1])

def PEiDUserdbToYARARules(arg, options):
    global counter

    print(
"""/*
  YARA rules generated with peid-userdb-to-yara-rules.py
  https://DidierStevens.com
  Use at your own risk

  File: %s
  --exclude: %s
  --eponly: %s
  --pe: %s
  Generated: %s
*/
""" % (arg, IFF(options.exclude == None, '', options.exclude), options.eponly, options.pe, '%04d/%02d/%02d %02d:%02d:%02d' % time.localtime()[0:6]))

    if options.pe:
        print('import "pe"\n')

    exclude = []
    if options.exclude != None:
       exclude = File2Strings(options.exclude)
    f = open(arg, 'r')
    for rule in re.findall(r'(\[.+\])\nsignature = ([0-9a-fA-F?]{2}( [0-9a-fA-F?]{2})+)\nep_only = (true|false)\n', f.read()):
        if rule[1] in exclude:
            continue
        if options.eponly == 'all' or options.eponly == rule[3]:
            print(PEiDUserdbRuleToYARARule(rule, options.pe))
    f.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-e', '--eponly', default='all', help='select rules with ep_only equal to false, true or select all (default is all)')
    oParser.add_option('-x', '--exclude', help='list with signatures to exclude')
    oParser.add_option('-p', '--pe', action='store_true', default=False, help='Generate rules using YARA pe module')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        PEiDUserdbToYARARules(args[0], options)

if __name__ == '__main__':
    Main()
