#!/usr/bin/env python

__description__ = 'Image overlay'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/02/17'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/02/17: start

Todo:
"""

import optparse
import textwrap
try:
    from PIL import Image
except ImportError:
    print('PIL module missing: download from http://www.pythonware.com/products/pil/')
    exit(-1)

def PrintManual():
    manual = '''
Manual:

To be written
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def ImageOverlay(filenameInput1, filenameInput2, filenameOutput, options):
    imageBackground = Image.open(filenameInput1).convert('RGBA')
    imageOverlay = Image.open(filenameInput2).convert('RGBA')
    Image.blend(imageBackground, imageOverlay, options.alpha).save(filenameOutput)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file-input-1 file-input-2  file-output\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--alpha', type=float, default=0.5, help='alpha value for blending')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 3:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        ImageOverlay(args[0], args[1], args[2], options)

if __name__ == '__main__':
    Main()


