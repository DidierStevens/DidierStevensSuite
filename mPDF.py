#!/usr/bin/python

# module with simple class to build PDF documents with basic PDF elements
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk
#
# History:
#  
#  2008/05/18: continue
#  2008/05/19: continue
#  2008/05/28: stream2
#  2008/11/09: cleanup for release
#  2008/11/21: Added support for other OSes than Windows
#  2009/05/04: Added support for abbreviated filters (/AHx and /Fl), thanks Binjo
#  2011/03/03: Added support for info in trailer and xrefAndTrailer
#  2011/07/01: V0.1.4: Added support for filters i and I; added support for Python 3
#  2012/02/25: fixed printing \n for filters i and I
#  2015/04/15: updated header and added comment

# Todo:
#   - add support for extra filters to stream2

__author__ = 'Didier Stevens'
__version__ = '0.1.5'
__date__ = '2015/04/15'

import sys
import zlib
import platform

def SplitByLength(input, length):
    result = []
    while len(input) > length:
        result.append(input[0:length] + '\n')
        input = input[length:]
    result.append(input + '>')
    return result

class cPDF:
    def __init__(self, filename):
        self.filename = filename
        self.indirectObjects = {}
    
    def appendString(self, str):
        fPDF = open(self.filename, 'a')
        fPDF.write(str)
        fPDF.close()

    def appendBinary(self, str):
        fPDF = open(self.filename, 'ab')
        if sys.version_info[0] == 2:
            fPDF.write(str)
        else:
            fPDF.write(bytes(str, 'ascii'))
        fPDF.close()

    def filesize(self):
        fPDF = open(self.filename, 'rb')
        fPDF.seek(0, 2)
        size = fPDF.tell()
        fPDF.close()
        return size
        
    def IsWindows(self):
        return platform.system() in ('Windows', 'Microsoft')
        
    def header(self, version='1.1'):
        fPDF = open(self.filename, 'w')
        fPDF.write('%%PDF-%s\n' % version)
        fPDF.close()

    def binary(self):
        self.appendString("%\xD0\xD0\xD0\xD0\n")

    def comment(self, comment):
        self.appendString('%' + comment + '\n')

    def indirectobject(self, index, version, io):
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        self.appendString("%d %d obj\n%s\nendobj\n" % (index, version, io))

    def stream(self, index, version, streamdata, dictionary="<< /Length %d >>"):
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        self.appendString(("%d %d obj\n" + dictionary + "\nstream\n") % (index, version, len(streamdata)))
        self.appendBinary(streamdata)
        self.appendString("\nendstream\nendobj\n")

    def Data2HexStr(self, data):
        hex = ''
        if sys.version_info[0] == 2:
            for b in data:
                hex += "%02x" % ord(b)
        else:
            for b in data:
                hex += "%02x" % b
        return hex

    def stream2(self, index, version, streamdata, entries="", filters=""):
        """
    * h ASCIIHexDecode
    * H AHx
    * i like ASCIIHexDecode but with 512 long lines
    * I like AHx but with 512 long lines
    * ASCII85Decode
    * LZWDecode
    * f FlateDecode
    * F Fl
    * RunLengthDecode
    * CCITTFaxDecode
    * JBIG2Decode
    * DCTDecode
    * JPXDecode
    * Crypt
        """
        
        encodeddata = streamdata
        filter = []
        for i in filters:
            if i.lower() == "h":
                encodeddata = self.Data2HexStr(encodeddata) + '>'
                if i == "h":
                    filter.insert(0, "/ASCIIHexDecode")
                else:
                    filter.insert(0, "/AHx")
            elif i.lower() == "i":
                encodeddata = ''.join(SplitByLength(self.Data2HexStr(encodeddata), 512))
                if i == "i":
                    filter.insert(0, "/ASCIIHexDecode")
                else:
                    filter.insert(0, "/AHx")
            elif i.lower() == "f":
                encodeddata = zlib.compress(encodeddata)
                if i == "f":
                    filter.insert(0, "/FlateDecode")
                else:
                    filter.insert(0, "/Fl")
            else:
                print("Error")
                return
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        self.appendString("%d %d obj\n<<\n /Length %d\n" % (index, version, len(encodeddata)))
        if len(filter) == 1:
            self.appendString(" /Filter %s\n" % filter[0])
        if len(filter) > 1:
            self.appendString(" /Filter [%s]\n" % ' '.join(filter))
        if entries != "":
            self.appendString(" %s\n" % entries)
        self.appendString(">>\nstream\n")
        if filters[-1].lower() == 'i':
            self.appendString(encodeddata)
        else:
            self.appendBinary(encodeddata)
        self.appendString("\nendstream\nendobj\n")

    def xref(self):
        self.appendString("\n")
        startxref = self.filesize()
        max = 0
        for i in self.indirectObjects.keys():
            if i > max:
                max = i
        self.appendString("xref\n0 %d\n" % (max+1))
        if self.IsWindows():
            eol = '\n'
        else:
            eol = ' \n'
        for i in range(0, max+1):
            if i in self.indirectObjects:
                self.appendString("%010d %05d n%s" % (self.indirectObjects[i], 0, eol))
            else:
                self.appendString("0000000000 65535 f%s" % eol)
        return (startxref, (max+1))

    def trailer(self, startxref, size, root, info=None):
        if info == None:
            self.appendString("trailer\n<<\n /Size %d\n /Root %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, startxref))
        else:
            self.appendString("trailer\n<<\n /Size %d\n /Root %s\n /Info %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, info, startxref))

    def xrefAndTrailer(self, root, info=None):
        xrefdata = self.xref()
        self.trailer(xrefdata[0], xrefdata[1], root, info)

    def template1(self):
        self.indirectobject(1, 0, "<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n>>")
        self.indirectobject(2, 0, "<<\n /Type /Outlines\n /Count 0\n>>")
        self.indirectobject(3, 0, "<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>")
        self.indirectobject(4, 0, "<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n>>")
        self.indirectobject(6, 0, "<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>")

