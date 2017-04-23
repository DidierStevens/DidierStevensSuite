#!/usr/bin/python

__description__ = 'tool to create a PDF document with an embedded file'
__author__ = 'Didier Stevens'
__version__ = '0.5.1'
__date__ = '2017/04/23'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/05/18: V0.1
  2008/05/19: Refactoring
  2008/05/23: Refactoring
  2008/05/27: Refactoring
  2008/06/27: V0.2, Refactoring, options, cleanup
  2008/11/09: V0.3, added autostart and button
  2009/06/15: V0.4.0: added stego
  2011/07/01: V0.5.0: added support for Python 3
  2017/04/23: V0.5.1: added option -n

Todo:
"""

import mPDF
import optparse

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

def ReadBinaryFile(name):
    """Read a binary file and return the content, return None if error occured
    """
    
    try:
        fBinary = open(name, 'rb')
    except:
        return None
    try:
        content = fBinary.read()
    except:
        return None
    finally:
        fBinary.close()
    return content

def CreatePDFWithEmbeddedFile(pdfFileName, embeddedFileName, embeddedFileContent, filters, nobinary, autoopen, button, stego, text):
    """Create a PDF document with an embedded file
    """
    
    oPDF = mPDF.cPDF(pdfFileName)

    oPDF.header()
    
    if not nobinary:
        oPDF.binary()

    if stego:
        embeddedFiles = 'Embeddedfiles'
    else:
        embeddedFiles = 'EmbeddedFiles'
    if autoopen:
        openAction = ' /OpenAction 9 0 R\n'
    else:
        openAction = ''
    oPDF.indirectobject(1, 0, '<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n /Names << /%s << /Names [(%s) 7 0 R] >> >>\n%s>>' % (embeddedFiles, embeddedFileName, openAction))
    oPDF.indirectobject(2, 0, '<<\n /Type /Outlines\n /Count 0\n>>')
    oPDF.indirectobject(3, 0, '<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>')
    if button:
        annots = ' /Annots [10 0 R]\n'
    else:
        annots = ''
    oPDF.indirectobject(4, 0, '<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n%s>>' % annots)
    if text == '':
        text = 'This PDF document embeds file %s' % embeddedFileName
    textCommands = '/F1 12 Tf 70 700 Td 15 TL (%s) Tj' % text
    if button:
        textCommands += " () ' () ' (Click inside the rectangle to save %s to a temporary folder and launch it.) ' () ' (Click here) '" % embeddedFileName
    oPDF.stream(5, 0, 'BT %s ET' % textCommands)
    oPDF.indirectobject(6, 0, '<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>')
    oPDF.indirectobject(7, 0, '<<\n /Type /Filespec\n /F (%s)\n /EF << /F 8 0 R >>\n>>' % embeddedFileName)
    oPDF.stream2(8, 0, embeddedFileContent, '/Type /EmbeddedFile', filters)
    if autoopen or button:
        oPDF.indirectobject(9, 0, '<<\n /Type /Action\n /S /JavaScript\n /JS (this.exportDataObject({ cName: "%s", nLaunch: 2 });)\n>>' % embeddedFileName)
    if button:
        oPDF.indirectobject(10, 0, '<<\n /Type /Annot\n /Subtype /Link\n /Rect [65 620 130 640]\n /Border [16 16 1]\n /A 9 0 R\n>>')

    oPDF.xrefAndTrailer("1 0 R")

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file-to-embed pdf-file', version='%prog ' + __version__)
    oParser.add_option('-f', '--filters', default='f', help='filters to apply, f for FlateDecode (default), h for ASCIIHexDecode')
    oParser.add_option('-t', '--nobinary', action='store_true', default=False, help="don't add the comment for binary format")
    oParser.add_option('-a', '--autoopen', action='store_true', default=False, help='open the embedded file automatically when the PDF is opened')
    oParser.add_option('-b', '--button', action='store_true', default=False, help='add a "button" to launch the embedded file')
    oParser.add_option('-s', '--stego', action='store_true', default=False, help='"hide" the embedded file by replacing /EmbeddedFiles with /Embeddedfiles')
    oParser.add_option('-m', '--message', default='', help='text to display in the PDF document')
    oParser.add_option('-n', '--name', default='', help='filename to use in the PDF objects (by default same as file-to-embed name)')
    (options, args) = oParser.parse_args()

    if len(args) != 2:
        oParser.print_help()
        print('')
        print('  %s' % __description__)
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')

    else:
        embeddedFileName = args[0]
        pdfFileName = args[1]
    
        embeddedFileContent = ReadBinaryFile(embeddedFileName)
        if embeddedFileContent == None:
            print('Error opening/reading file %s' % embeddedFileName)
        else:
            CreatePDFWithEmbeddedFile(pdfFileName, IFF(options.name == '', embeddedFileName, options.name), embeddedFileContent, options.filters, options.nobinary, options.autoopen, options.button, options.stego, options.message)

if __name__ == '__main__':
    Main()
