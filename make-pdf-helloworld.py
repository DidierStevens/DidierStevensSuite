#20080518
#20080519

import mPDF
import time
import zlib
import sys

if len(sys.argv) != 2:
    print "Usage: make-pdf-helloworld pdf-file"
    print "  "
    print "  Source code put in the public domain by Didier Stevens, no Copyright"
    print "  Use at your own risk"
    print "  https://DidierStevens.com"

else:
    pdffile = sys.argv[1]

    oPDF = mPDF.cPDF(pdffile)

    oPDF.header()

    oPDF.template1()

    #oPDF.stream(5, 0, "BT /F1 24 Tf 100 700 Td (Hello World) Tj ET")
    oPDF.stream(5, 0, """BT /F1 12 Tf 100 700 Td 15 TL 
(Hello World) Tj 
(Second Line) ' 
(Third Line) ' 
ET
100 712 100 -100 re S""")

    oPDF.xrefAndTrailer("1 0 R")
