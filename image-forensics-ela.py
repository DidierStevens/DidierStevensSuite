#!/usr/bin/env python

__description__ = 'Image Forensics using Error Level Analysis method'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2015/02/17'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

Based on method described here:
http://blackhat.com/presentations/bh-dc-08/Krawetz/Whitepaper/bh-dc-08-krawetz-WP.pdf
https://infohost.nmt.edu/~schlake/ela/

History:
  2015/02/13: start
  2015/02/17: continue

Todo:
"""

import optparse
import textwrap
import cStringIO
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

class cELA():
    def __init__(self, trigger, enhance, coloronly):
        self.trigger = trigger
        self.enhance = enhance
        self.coloronly = coloronly

    def CalculateELA(self, pixelA, pixelB):
        pixelDiff = map(lambda x, y: abs(x - y), pixelA, pixelB)
        if sum(pixelDiff) > self.trigger and (not self.coloronly or pixelDiff[0] != pixelDiff[1] or pixelDiff[0] != pixelDiff[2]):
            return tuple([x * self.enhance for x in pixelDiff])
        else:
            return (0, 0, 0)

def ELA(filenameInput, filenameOutput, options):
    oELA = cELA(options.trigger, options.enhance, options.coloronly)
    imOriginal = Image.open(filenameInput)
    oStringIO = cStringIO.StringIO()
    imOriginal.save(oStringIO, 'JPEG', quality=options.quality)
    oStringIO.seek(0)
    imJPEGSaved = Image.open(oStringIO)
    imNew = Image.new('RGB', imOriginal.size)
    imNew.putdata(map(oELA.CalculateELA, imOriginal.getdata(), imJPEGSaved.getdata()))
    imNew.save(filenameOutput)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file-input file-output\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-q', '--quality', type=int, default=95, help='Quality level for JPEG (default 95)')
    oParser.add_option('-t', '--trigger', type=int, default=10, help='Trigger level when comparing pixels (default 10)')
    oParser.add_option('-e', '--enhance', type=int, default=20, help='Multiplier for pixel color value (default 20)')
    oParser.add_option('-c', '--coloronly', action='store_true', default=False, help='Change gray and white pixels to black')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        ELA(args[0], args[1], options)

if __name__ == '__main__':
    Main()
