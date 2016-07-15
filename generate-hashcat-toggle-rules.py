#!/usr/bin/env python

__description__ = 'Generate hashcat toggle rules'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/07/15'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

# https://hashcat.net/forum/thread-4686.html
# https://hashcat.net/forum/thread-615-page-2.html
# https://hashcat.net/forum/archive/index.php?thread-803.html

History:
  2016/07/10: start
  2016/07/15: added option nothing

Todo:
"""

import optparse
import textwrap

dumplinelength = 16

def PrintManual():
    manual = '''
Manual:

generate-hashcat-toggle-rules.py is a tool to generate hashcat toggle rules.

generate-hashcat-toggle-rules.py 1 will generate a set of toggles identical to toggles1.rule
generate-hashcat-toggle-rules.py 2 will generate a set of toggles identical to toggles2.rule
And so on...

By default the tool generates toggles for 15 positions (T0 through TE). To change the number of positions, use option -p.

Option -n (nothing) includes a rule to do nothing, i.e. make no changes to the candidate password. This rule is :.

To generate a set of toggles to use on a LM passwords wordlist to crack NTLM hashes, issue command generate-hashcat-toggle-rules.py -n -p 14 14

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))


def TogglesPlusOne(toggles, max):
    result = []
    for toggle in toggles:
        for i in range(toggle[-1] + 1, max):
            result.append(toggle + [i])
    return result
    
def GeneratePrintableToggle(toggle):
    return ''.join(['T%X' % i for i in toggle])

def GenerateHashcatToggleRules(maxsize, options):
    if options.nothing:
        print(':')
    toggles = [[i] for i in range(0, options.positions)]
    while toggles != []:
        for toggle in toggles:
            print(GeneratePrintableToggle(toggle))
        if len(toggles[0]) >= maxsize:
            break
        toggles = TogglesPlusOne(toggles, options.positions)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] size\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-p', '--positions', type=int, default=15, help='number of positions (default 15)')
    oParser.add_option('-n', '--nothing', action='store_true', default=False, help='Include rule nothing (:)')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if len(args) != 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    else:
        return GenerateHashcatToggleRules(int(args[0]), options)

if __name__ == '__main__':
    Main()
