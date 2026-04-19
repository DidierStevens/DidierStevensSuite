#!/usr/bin/python

# V0.3 2026/04/15
# make-pdf-javascript, use it to create a PDF document with embedded JavaScript that will execute automatically when the document is opened
# requires module mPDF.py
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk
#
# History:
#  
#  2008/05/29: continue
#  2008/11/09: cleanup for release
#  2019/11/17: 0.2 Python 3
#  2026/04/15: 0.3 added option -F

import mPDF
import optparse
import binascii

def Main():
    """make-pdf-javascript, use it to create a PDF document with embedded JavaScript that will execute automatically when the document is opened
    """

    parser = optparse.OptionParser(usage='usage: %prog [options] pdf-file', version='%prog 0.1')
    parser.add_option('-j', '--javascript', help='javascript to embed (default embedded JavaScript is app.alert messagebox)')
    parser.add_option('-f', '--javascriptfile', help='javascript file to embed (default embedded JavaScript is app.alert messagebox)')
    parser.add_option('-F', '--javascriptfilehex', help='javascript file to embed as hex string')
    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.print_help()
        print('')
        print('  make-pdf-javascript, use it to create a PDF document with embedded JavaScript that will execute automatically when the document is opened')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
    
    else:
        oPDF = mPDF.cPDF(args[0])
    
        oPDF.header()
    
        oPDF.indirectobject(1, 0, '<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n /OpenAction 7 0 R\n>>')
        oPDF.indirectobject(2, 0, '<<\n /Type /Outlines\n /Count 0\n>>')
        oPDF.indirectobject(3, 0, '<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>')
        oPDF.indirectobject(4, 0, '<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n>>')
        oPDF.stream(5, 0, 'BT /F1 12 Tf 100 700 Td 15 TL (JavaScript example) Tj ET')
        oPDF.indirectobject(6, 0, '<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>')
    
        if options.javascript == None and options.javascriptfile == None and options.javascriptfilehex == None:
            javascript = """app.alert({cMsg: 'Hello from PDF JavaScript', cTitle: 'Testing PDF JavaScript', nIcon: 3});"""
        elif options.javascript != None:
            javascript = options.javascript
        elif options.javascriptfile != None:
            try:
                fileJavasScript = open(options.javascriptfile, 'r')
            except:
                print('error opening file %s' % options.javascriptfile)
                return

            try:
                javascript = fileJavasScript.read()
            except:
                print('error reading file %s' % options.javascriptfile)
                return
            finally:
                fileJavasScript.close()
        else:
            try:
                fileJavasScript = open(options.javascriptfilehex, 'rb')
            except:
                print('error opening file %s' % options.javascriptfilehex)
                return

            try:
                javascript = fileJavasScript.read()
            except:
                print('error reading file %s' % options.javascriptfile)
                return
            finally:
                fileJavasScript.close()
        
        if options.javascriptfilehex != None:
            oPDF.indirectobject(7, 0, '<<\n /Type /Action\n /S /JavaScript\n /JS <%s>\n>>' % binascii.b2a_hex(javascript).decode())
        else:
            oPDF.indirectobject(7, 0, '<<\n /Type /Action\n /S /JavaScript\n /JS (%s)\n>>' % javascript)
    
        oPDF.xrefAndTrailer('1 0 R')

if __name__ == '__main__':
    Main()
