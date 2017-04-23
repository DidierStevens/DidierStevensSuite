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
#  2013/04/03: V0.2.0: Added cNameObfuscation; filter j and *; cFuzzer
#  2013/04/05: added docstrings
#  2013/04/11: added SetReference
#  2013/04/14: V0.2.1: added return value to stream method
#  2013/04/20: V0.2.2: added version parameter to header function
#  2014/09/25: V0.2.3: added comment method
#  2014/10/15: V0.2.4: added CObjectStream
#  2017/04/16: V0.2.5: added support for filter i##

# Todo:
#   - add support for extra filters to stream2

__author__ = 'Didier Stevens'
__version__ = '0.2.5'
__date__ = '2017/04/16'

import sys
import zlib
import platform
import random
import re
import struct

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

def ParseFilters(definition):
    filters = []
    number = ''
    for character in definition + ' ':
        if character.isdigit():
            number += character
        else:
            if number != '':
                filters.append(number)
                number = ''
            filters.append(character)
    result = []
    filters = filters[:-1]
    while filters != []:
        token = filters[0]
        filters = filters[1:]
        if token.lower() == 'i':
            if filters != [] and filters[0].isdigit():
                result.append((token, int(filters[0])))
                filters = filters[1:]
            else:
                result.append((token, 512))
        else:
            result.append((token, None))
    return result

def IsLastFilterI(filters):
    if filters == []:
        return False
    return filters[-1][0].lower() == 'i'
            
class cPDF:
    """
    Class to create a PDF file
    """
    def __init__(self, filename):
        """
        class instantiation arguments:

        filename is the name of the PDF file to be created
        """
        self.filename = filename
        self.indirectObjects = {}
        self.objstms = []

    def appendString(self, str):
        """
        Internal helper function
        """
        fPDF = open(self.filename, 'a')
        fPDF.write(str)
        fPDF.close()

    def appendBinary(self, str):
        """
        Internal helper function
        """
        fPDF = open(self.filename, 'ab')
        if sys.version_info[0] == 2:
            fPDF.write(str)
        else:
            fPDF.write(bytes(str, 'ascii'))
        fPDF.close()

    def filesize(self):
        """
        Internal helper function
        """
        fPDF = open(self.filename, 'rb')
        fPDF.seek(0, 2)
        size = fPDF.tell()
        fPDF.close()
        return size

    def IsWindows(self):
        """
        Internal helper function
        """
        return platform.system() in ('Windows', 'Microsoft')

    def header(self, version='1.1'):
        """
        Method to create a PDF header (%PDF-1.1) and output it
        to the PDF file.

        By default, the version is 1.1, but can be specified with
        the version argument.
        """
        fPDF = open(self.filename, 'w')
        fPDF.write('%%PDF-%s\n' % version)
        fPDF.close()

    def binary(self):
        """
        Method to create a comment (%\\xD0\\xD0\\xD0\\xD0) and output it
        to the PDF file.
        Use this after the header to indicate a PDF file has binary
        (not printable) content.
        """
        self.appendString("%\xD0\xD0\xD0\xD0\n")

    def comment(self, comment):
        """
        Method to create a comment and output it to the PDF file.
        """
        self.appendString('%' + comment + '\n')

    def indirectobject(self, index, version, io):
        """
        Method to create an indirect object and output it to the PDF file.

        index is the index number of the object.

        version is the version number of the object. Use 0 by convention.

        io is the content of the indirect object.
        """
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        self.appendString("%d %d obj\n%s\nendobj\n" % (index, version, io))

    def stream(self, index, version, streamdata, dictionary="<< /Length %d >>"):
        """
        Method to create an indirect object with a stream and output it
        to the PDF file.

        index is the index number of the object.

        version is the version number of the object. Use 0 by convention.

        streamdata is the stream that will be put inside the object
        without any modifications.

        dictionary is the PDF dictionary to be put before the stream.
        By default this is << /Length %d >>. If you provide a dictionary,
        you must include /Length %d.

        The return value is the file position of the stream data.

        Use this method when you want to provide the stream yourself.
        """
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        self.appendString(("%d %d obj\n" + dictionary + "\nstream\n") % (index, version, len(streamdata)))
        position = self.filesize()
        self.appendBinary(streamdata)
        self.appendString("\nendstream\nendobj\n")

        return position

    def Data2HexStr(self, data, whitespace=0):
        """
        Internal helper function
        """
        hex = ''
        if sys.version_info[0] == 2:
            for b in data:
                hex += "%02x%s" % (ord(b), ' ' * random.randint(0, whitespace))
        else:
            for b in data:
                hex += "%02x%s" % (b, ' ' * random.randint(0, whitespace))
        return hex

    def stream2(self, index, version, streamdata, entries="", filters="", fuzzer=None):
        """
        Method to create an indirect object with a stream and
        output it to the PDF file.

        index is the index number of the object.

        version is the version number of the object. Use 0 by convention.

        streamdata is the stream that will be put inside the object
        modified according to the filters.

        entries is a string with a list of entries to be put inside
        the PDF dictionary. Empty string by default.

        filters is a string with the encoding filters to be applied.
        Each filter is represented by a letter, and filters are applied
        from left to right.
        For example, "hf" will apply the ASCIIHexDecode encoding filter and
        then the FlateDecode encoding filter. For more details regarding
        filters, see below.
        Empty string by default.

        fuzzer is a fuzzer object to be used by the fuzzer filter (*).
        If no object is provided, a default instance of class cFuzzer
        is used.

        Use this method when you want the stream to be encoded.

        Implemented filters:
        h ASCIIHexDecode
        H AHx
        i like ASCIIHexDecode but with 512 character long lines (default)
          add number to speficy length of line, example: i80 for 80 characters
        I like AHx but with 512 character long lines (default)
          add number to speficy length of line, example: I80 for 80 characters
        j like ASCIIHexDecode but with random whitespace
        J like AHx but with random whitespace
        f FlateDecode
        F Fl

        Special filters (these are applied but not added to /Filters):
        * for fuzzing

        Not implemented filters:
        ASCII85Decode
        LZWDecode
        RunLengthDecode
        CCITTFaxDecode
        JBIG2Decode
        DCTDecode
        JPXDecode
        Crypt
        """

        if fuzzer == None:
            oFuzzer = cFuzzer()
        else:
            oFuzzer = fuzzer
        encodeddata = streamdata
        filter = []
        filters = ParseFilters(filters)
        for i in filters:
            if i[0].lower() == 'h':
                encodeddata = self.Data2HexStr(encodeddata) + '>'
                if i[0] == 'h':
                    filter.insert(0, "/ASCIIHexDecode")
                else:
                    filter.insert(0, "/AHx")
            elif i[0].lower() == "i":
                encodeddata = ''.join(self.SplitByLength(self.Data2HexStr(encodeddata), i[1]))
                if i[0] == "i":
                    filter.insert(0, "/ASCIIHexDecode")
                else:
                    filter.insert(0, "/AHx")
            elif i[0].lower() == "j":
                encodeddata = self.Data2HexStr(encodeddata, 2) + '>'
                if i[0] == "j":
                    filter.insert(0, "/ASCIIHexDecode")
                else:
                    filter.insert(0, "/AHx")
            elif i[0].lower() == "f":
                encodeddata = zlib.compress(encodeddata)
                if i[0] == "f":
                    filter.insert(0, "/FlateDecode")
                else:
                    filter.insert(0, "/Fl")
            elif i[0] == "*":
                encodeddata = oFuzzer.Fuzz(encodeddata)
            else:
                print("Error")
                return
        self.appendString("\n")
        self.indirectObjects[index] = self.filesize()
        length = len(encodeddata)
        if IsLastFilterI(filters) and self.IsWindows():
            length += encodeddata.count('\n')
        self.appendString("%d %d obj\n<<\n /Length %d\n" % (index, version, length))
        if len(filter) == 1:
            self.appendString(" /Filter %s\n" % filter[0])
        if len(filter) > 1:
            self.appendString(" /Filter [%s]\n" % ' '.join(filter))
        if entries != "":
            self.appendString(" %s\n" % entries)
        self.appendString(">>\nstream\n")
        if IsLastFilterI(filters):
            self.appendString(encodeddata)
        else:
            self.appendBinary(encodeddata)
        self.appendString("\nendstream\nendobj\n")

    def xref(self):
        """
        Method to create an xref table and output it to the PDF file.

        Returns the file position of the xref table and the size of the
        xref table in a list.
        """
        self.appendString("\n")
        startxref = self.filesize()
        maximumIndexValue = 0
        for i in self.indirectObjects.keys():
            if i > maximumIndexValue:
                maximumIndexValue = i
        self.appendString("xref\n0 %d\n" % (maximumIndexValue+1))
        if self.IsWindows():
            eol = '\n'
        else:
            eol = ' \n'
        for i in range(0, maximumIndexValue+1):
            if i in self.indirectObjects:
                self.appendString("%010d %05d n%s" % (self.indirectObjects[i], 0, eol))
            else:
                self.appendString("0000000000 65535 f%s" % eol)
        return (startxref, (maximumIndexValue+1))

    def trailer(self, startxref, size, root, info=None):
        """
        Method to create a trailer and output it to the PDF file.

        startxref is the file position of the xref table (this value is
        returned by the xref method)

        size is the size of the xref table (this value is
        returned by the xref method)

        root is a string with a reference to the root object (/Root).
        Example: "1 0 R"

        info is a string with a reference to the info object (/Info).
        This argument is optional.
        Example: "9 0 R"
        """
        if info == None:
            self.appendString("trailer\n<<\n /Size %d\n /Root %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, startxref))
        else:
            self.appendString("trailer\n<<\n /Size %d\n /Root %s\n /Info %s\n>>\nstartxref\n%d\n%%%%EOF\n" % (size, root, info, startxref))

    def xrefAndTrailer(self, root, info=None):
        """
        Method to create an xref table together with a trailer and
        output it to the PDF file.

        root is a string with a reference to the root object (/Root).
        Example: "1 0 R"

        info is a string with a reference to the info object (/Info).
        This argument is optional.
        Example: "9 0 R"
        """
        xrefdata = self.xref()
        self.trailer(xrefdata[0], xrefdata[1], root, info)

    def template1(self):
        """
        Method to create 5 indirect objects that form a template for
        the start of a PDF file.
        """
        self.indirectobject(1, 0, "<<\n /Type /Catalog\n /Outlines 2 0 R\n /Pages 3 0 R\n>>")
        self.indirectobject(2, 0, "<<\n /Type /Outlines\n /Count 0\n>>")
        self.indirectobject(3, 0, "<<\n /Type /Pages\n /Kids [4 0 R]\n /Count 1\n>>")
        self.indirectobject(4, 0, "<<\n /Type /Page\n /Parent 3 0 R\n /MediaBox [0 0 612 792]\n /Contents 5 0 R\n /Resources <<\n             /ProcSet [/PDF /Text]\n             /Font << /F1 6 0 R >>\n            >>\n>>")
        self.indirectobject(6, 0, "<<\n /Type /Font\n /Subtype /Type1\n /Name /F1\n /BaseFont /Helvetica\n /Encoding /MacRomanEncoding\n>>")

    def MatchDictionary(self, string):
        """
        Internal helper function
        """
        status = 0
        level = 0
        result = ''
        for c in string:
            result += c
            if status == 0 and c == '<':
                status = 1
            elif status == 1:
                if c == '<':
                    level += 1
                status = 0
            elif status == 0 and c == '>':
                status = 2
            elif status == 2:
                if c == '>':
                    level -= 1
                    if level == 0:
                        return result
                status = 0
        return None

    def originalIncrementalUpdate(self, pdffilename):
        """
        Method to start an incremental update of an existing PDF file.

        pdffilename is the name of the PDF file to be used for the
        incremental update.

        This methods returns the dictionary of the root object,
        the dictionary of the trailer and the file position of the
        xrf table found in the existing PDF file. These 3 values are
        returned in a list.

        Use this method to start an incremental update.
        """
        original = ReadBinaryFile(pdffilename)
        fPDF = open(self.filename, 'wb')
        if sys.version_info[0] == 2:
            fPDF.write(original)
        else:
            fPDF.write(bytes(original, 'ascii'))
        fPDF.close()
        startxrefs = re.findall(r'startxref\s+(\d+)', original)
        if startxrefs == []:
            return None, None, None
        oMatch = re.search(r'trailer\s+', original[int(startxrefs[-1]):])
        if oMatch == None:
            return None, None, None
        positionDictionaryTrailer = oMatch.end() + int(startxrefs[-1])
        dictionaryTrailer = self.MatchDictionary(original[positionDictionaryTrailer:])
        if dictionaryTrailer == None:
            return None, None, None
        oDictionaryTrailer = cDictionary(dictionaryTrailer)
        idRoot = oDictionaryTrailer.GetID('Root')
        if idRoot == None:
            return None, None, None
        oMatch = re.search(r'\s+%d\s+0\s+obj\s+' % idRoot, original)
        if oMatch == None:
            return None, None, None
        dictionaryRoot = self.MatchDictionary(original[oMatch.end():])
        if dictionaryRoot == None:
            return None, None, None
        oDictionaryRoot = cDictionary(dictionaryRoot)
        return oDictionaryTrailer, oDictionaryRoot, int(startxrefs[-1])

    def xrefIncrementalAndTrailer(self, dictionaryTrailer):
        """
        Method to create an xref table together with a trailer for
        an incremental update and output it to the PDF file.

        dictionaryTrailer is a (modified) dictionary returned by method
        originalIncrementalUpdate.

        Use this method to terminate an incremental update.
        """
        if self.IsWindows():
            eol = '\n'
        else:
            eol = ' \n'

        self.appendString("\n")
        startxref = self.filesize()
        self.appendString("xref\n0 1\n")
        self.appendString("0000000000 65535 f%s" % eol)
        for i in self.indirectObjects.keys():
            self.appendString("%d 1\n" % i)
            self.appendString("%010d %05d n%s" % (self.indirectObjects[i], 0, eol))
        self.appendString("trailer\n%s\nstartxref\n%d\n%%%%EOF\n" % (dictionaryTrailer, startxref))
        return startxref

    def SplitByLength(self, input, length):
        """
        Internal helper function
        """
        result = []
        while len(input) > length:
            result.append(input[0:length] + '\n')
            input = input[length:]
        result.append(input + '>')
        return result

    def objstm(self, oObjectStream):
        """
        Method to add an object stream to the PDF file.

        oObjectStream is an instantiated object of class cObjectStream.
        """
        self.stream2(oObjectStream.index, oObjectStream.version, oObjectStream.getStream(), oObjectStream.getDictionaryEntries(), oObjectStream.filters)
        self.objstms.append(oObjectStream)

    def xrefobjAndTrailer(self, index, version, root):
        """
        Method to create an xref object together with a trailer and
        output it to the PDF file.

        index is the index number of the xref object.

        version is the version number of the xref object. Use 0 by convention.

        root is a string with a reference to the root object (/Root).
        Example: "1 0 R"
        """
        maximumIndexValue = max(index, max(self.indirectObjects.keys()))
        dObjects = {}
        for objstm in self.objstms:
            for indexIter in objstm.objects:
                dObjects[indexIter] = objstm
        maximumIndexValue = max(maximumIndexValue, max(dObjects.keys()))

        self.appendString('\n')
        self.indirectObjects[index] = self.filesize()

        xrefFormat = '>BII'
        xrefStream = ''
        for iter in range(maximumIndexValue + 1):
            if iter in self.indirectObjects.keys():
                xrefStream += struct.pack(xrefFormat, 1, self.indirectObjects[iter], 0)
            elif iter in dObjects.keys():
                xrefStream += struct.pack(xrefFormat, 2, dObjects[iter].index, dObjects[iter].objects.index(iter))
            else:
                xrefStream += struct.pack(xrefFormat, 0, 0, 0)

        formatSizes = ' '.join([str(size) for size in map(struct.calcsize, [c for c in xrefFormat]) if size != 0])
        self.appendString(('%d %d obj\n<< /Type /XRef /Length %d /W [%s] /Root %s /Size %d >>\nstream\n') % (index, version, len(xrefStream), formatSizes, root, maximumIndexValue + 1))
        self.appendBinary(xrefStream)
        self.appendString('\nendstream\nendobj\n')

        self.appendString('\nstartxref\n%d\n%%%%EOF\n' % self.indirectObjects[index])

class cNameObfuscation:
    """
    Class to implement random PDF name obfuscation
    Example: /Page becomes /P#61ge
    """

    def __init__(self, probability=0.5, characters=1):
        """
        class instantiation arguments:

        probability is a number between 0.0 and 1.0. It indicates
        the probability a name gets obfuscated. 0.0 means a name will
        never be obfuscated, 1.0 means a name will always be obfuscated.
        default 0.5

        characters is the number of characters in the name to obfuscated
        by replacing them with the hex-equivalent (#??); default 1
        """
        self.probability = probability
        self.characters = characters

    def IsNameCharacter(self, c):
        """
        Internal helper function
        """
        return c.lower() >= 'a' and c.lower() <= 'z' or c >= '0' and c <= '9'

    def ObfuscateName(self, name):
        """
        Internal helper function
        """
        if random.random() < self.probability:
            if self.characters >= len(name):
                population = range(len(name))
            else:
                population = random.sample(range(len(name)), self.characters)
            for iIndex in population:
                name[iIndex] = '#%02X' % ord(name[iIndex])
        return '/' + ''.join(name)

    def Obfuscate(self, str):
        """
        Use this method to randomly obfuscate the names found in the
        provided string according to the instantiated class parameters.
        The return value is the string with obfuscated names.
        """
        result = ''
        foundName = False
        for c in str:
            if not foundName and c == '/':
                foundName = True
                name = []
            elif foundName:
                if self.IsNameCharacter(c):
                    name.append(c)
                else:
                    result += self.ObfuscateName(name)
                    result += c
                    foundName = False
                    name = []
            else:
                result += c
        if foundName:
            result += self.ObfuscateName(name)
        return result

class cFuzzer:
    """
    Class to implement a simple fuzzer
    """

    def __init__(self, count=10, minimum=1, maximum=10, character='A'):
        """
        class instantiation arguments:

        count is the number of fuzzed sequences (i.e. overwritten bytes)
        produced by the fuzzer; default 10

        minimum is the minimum length of a fuzzed sequence; default 1

        maximum is the maximum length of a fuzzed sequence; default 10

        character is the character used to generate the
        fuzzed sequences; default 'A'
        """
        self.count = count
        self.minimum = minimum
        self.maximum = maximum
        self.character = character

    def Fuzz(self, str):
        """
        Use this method to fuzz a string according to the
        instantiated class parameters.
        The return value is the fuzzed string.
        """
        exploded = [c for c in str]
        for count in range(self.count):
            size = random.randint(self.minimum, self.maximum)
            position = random.randint(0, len(str) - size)
            for iIter in range(size):
                exploded[position + iIter] = self.character
        return ''.join(exploded)

class cDictionary:
    """
    Helper class to get and set values in PDF dictionaries
    """

    def __init__(self, string):
        self.dictionary = string

    def GetID(self, name):
        result = re.findall(r'/' + name + r'\s+(\d+)\s+0\s+[rR]', self.dictionary)
        if result == []:
            return None
        return int(result[0])

    def GetNumber(self, name):
        result = re.findall(r'/' + name + r'\s+(\d+)', self.dictionary)
        if result == []:
            return None
        return int(result[0])

    def SetNumber(self, name, value):
        oMatch = re.search(r'/' + name + r'\s+(\d+)', self.dictionary)
        if oMatch == None:
            self.Insert(name, str(value))
        else:
            self.dictionary = self.dictionary[0:oMatch.start()] + '/' + name + ' ' + str(value) + self.dictionary[oMatch.end():]

    def Insert(self, name, value):
        self.dictionary = self.dictionary[0:2] + '/' + name + ' ' + value + self.dictionary[2:]

    def SetReference(self, name, value):
        oMatch = re.search(r'/' + name + r'\s+(\d+)\s+(\d+)\s+R', self.dictionary)
        if oMatch == None:
            oMatch = re.search(r'/' + name + r'\s*\[[^\[\]]+\]', self.dictionary)
        if oMatch == None:
            self.Insert(name, str(value))
        else:
            self.dictionary = self.dictionary[0:oMatch.start()] + '/' + name + ' ' + str(value) + self.dictionary[oMatch.end():]

class cObjectStream:
    """
    Class to create an object stream (/ObjStm)
    """

    def __init__(self, index, version, filters=''):
        """
        class instantiation arguments:

        index is the index number of the /ObjStm object.

        version is the version number of the /ObjStm object. Use 0 by convention.

        filters is a string with the encoding filters to be applied (see method stream2)
        """
        self.index = index
        self.version = version
        self.filters = filters
        self.indices = ''
        self.ios = ''
        self.objects = []

    def indirectobject(self, index, io):
        """
        Method to add an indirect object to the object stream.

        index is the index number of the object.

        io is the content of the indirect object.
        """
        if self.indices != '':
            self.indices += ' '
        self.indices += '%d %d' % (index, len(self.ios))
        self.ios += io
        self.objects.append(index)

    def getDictionaryEntries(self):
        """
        Internal helper function
        """
        return '/Type /ObjStm\n /N %d\n /First %d' % (len(self.objects), len(self.indices))

    def getStream(self):
        """
        Internal helper function
        """
        return self.indices + self.ios
