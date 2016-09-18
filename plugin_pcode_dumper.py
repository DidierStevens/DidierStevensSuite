#!/usr/bin/env python

__description__ = 'P-code dumper plugin for oledump.py'
__author__ = 'Vesselin Bontchev'
__version__ = '0.0.1'
__date__ = '2016/09/05'

"""

Source code put in public domain by Vesselin Bontchev, no Copyright
Use at your own risk

History:
  2016/09/10: start

Todo:
"""

from struct import *

def dumpPcode(stream):
    result = []
    if (unpack_from('<H', stream, 2)[0] > 0xFF):
        endian = '>'
    else:
        endian = '<'
    # This code works ONLY for Office 2000 and higher.
    # It will break badly for Office 97 or Office 95 (Excel 95).
    # Sadly, I need access to _VBA_PROJECT, in order to determine Office version.
    offset = 0x19
    dword = unpack_from(endian + 'L', stream, offset)[0]
    offset = dword + 0x3C
    magic = unpack_from(endian + 'H', stream, offset)[0]
    offset += 2
    # The rest is the same for Office 97 and Office 2000+. Office 95 is different.
    if (magic != 0xCAFE):
        return result
    offset += 2
    numLines = unpack_from(endian + 'H', stream, offset)[0]
    offset += 2
    pcodeStart = offset + numLines * 12 + 10
    bytesPerLine = 10
    for line in range(numLines):
        offset += 4
        lineLength = unpack_from(endian + 'H', stream, offset)[0]
        offset += 2
        offset += 2
        lineOffset = unpack_from(endian + 'L', stream, offset)[0]
        offset += 4
        lineStr = "%04d: " % line
        counter = 0
        hexStr = ""
        asciiStr = ""
        for i in range(lineLength):
            c = stream[pcodeStart + lineOffset + i]
            hexStr += "%02X " % ord(c)
            if (0x20 <= ord(c) <= 0x7E):
                asciiStr += c
            else:
                asciiStr += '.'
            counter += 1
            if (counter >= bytesPerLine):
                lineStr += hexStr + " [" + asciiStr + "]"
                result.append(lineStr)
                lineStr = "      "
                counter = 0
                hexStr = ""
                asciiStr = ""
        if (counter):
            lineStr += hexStr.ljust(bytesPerLine * 3) + " [" + asciiStr.ljust(bytesPerLine) + "]"
            result.append(lineStr)
    return result

# A plugin defines a class that is instantiated for each stream in the OLE document.
# This class inherits from class cPluginParent.
# The name of the class (cStreamSample in this example) can be chosen freely.
# But avoid name conflicts with other plugins.
class cPcodeDumper(cPluginParent):

    # Set class variable macroOnly to True if the plugins requires VBA macro text (decompressed stream),
    # or to False if the plugin requires the raw stream content.
    # This class variable is defined and set to False in the parent class cPluginParent.
    macroOnly = False

    # Class variable name contains the name of the plugin to be displayed in oledump's output.
    name = 'P-code dumper'

    # Method __init__ provides data via 3 arguments:
    #  name is the name of the stream as returned by olefile's listdir method.
    #  stream is the content of the stream as returned by olefile's read method.
    #   stream is None is no stream is present (container)
    #   if class variable macroOnly is True, then stream contains the VBA macro code as one long string (e.g. the decompressed stream)
    #  options is a string passed to --pluginoptions.
    def __init__(self, name, stream, options):
        # Storing the arguments for later use by Analyze method
        self.streamname = name
        self.stream = stream
        self.options = options

        # Object property ran must be set to False before the plugin runs.
        # oledump only displays output for the plugin if property ran is True.
        self.ran = False

    # Method Analyze is called by oledump to let the plugin analyze the stream.
    # This method must return a list of strings: this is the plugin output to be displayed by oledump.
    # This method must also set object property ran to True to have oledump display output for this plugin.
    def Analyze(self):

        # This example counts the numbers of bytes with value FF in the stream,
        # and produces one line of output if the count is more than 0.
        result = []
        # The following is WRONG. The proper way to determine what are the code modules
        # is to parse the PROJECT stream. But this is the best I can do with this interface.
        if (len(self.streamname) > 1):
            parent = self.streamname[len(self.streamname) - 2]
            myName = self.streamname[len(self.streamname) - 1]
            if ((parent.upper() == 'VBA') and
		(myName.lower() != 'dir') and
		(myName.upper() != '_VBA_PROJECT') and
		(myName[:6].upper() != '__SRP_')):
                result = dumpPcode(self.stream)
                self.ran = True

        return result

# The plugin class must be registered with oledump by calling function AddPlugin with
# the name of the plugin class (cStreamSample in this example).
AddPlugin(cPcodeDumper)

# The plugin code is not restricted or sandboxed. Plugin code runs with the same privileges and accesses as oledump.
# The plugin code and interface is not validated before execution.
# There is no object persistence across streams. If you need this, get in touch.
