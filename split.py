#!/usr/bin/env python

__description__ = 'Split a text file into X number of files (2 by default)'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/03/22'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/03/20: start
  2015/03/22: continue

Todo:
"""

import optparse
import textwrap
import os

def PrintManual():
    manual = '''
Manual:

This program will split the given text file in 2 parts (2 parts by default, the number of parts can be changed with option -p). Each resulting file has suffix _part_?? where ?? is the number of the file (01, 02, ...). The extension remains the same.

The first line of text is written to _part_01, the second line of text is written to _part_02, and so on, until the last part _part_?? is written to. Then the cycle starts again with the first part _part_01.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def Split(filename, options):
    root, ext = os.path.splitext(filename)
    filesWrite = [open('%s_part_%02d%s' % (root, iIter + 1, ext), 'w') for iIter in range(options.parts)]

    count = 0
    for line in open(filename, 'r'):
        filesWrite[count % options.parts].write(line)
        count += 1
    print('Number of lines: %d' % count)
    for fileWrite in filesWrite:
        fileWrite.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-p', '--parts', default=2, type=int, help='Number of parts to split the file into')
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
        Split(args[0], options)

if __name__ == '__main__':
    Main()
