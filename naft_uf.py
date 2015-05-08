#!/usr/bin/env python

__description__ = 'Network Appliance Forensic Toolkit - Utility Functions'
__author__ = 'Didier Stevens'
__version__ = '0.0.9'
__date__ = '2014/10/05'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2012/01/25: start
  2012/02/17: V0.0.4 added LogLine
  2013/10/12: V0.0.5 added cBufferFile
  2014/10/05: V0.0.9 File2Data added ZIP support

Todo:
"""

import time
import os
import zipfile
import sys

MALWARE_PASSWORD = 'infected'

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def IsZIPFile(filename):
    return filename.lower().endswith('.zip')

def File2Data(filename):
    if IsZIPFile(filename):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        try:
            return oZipContent.read()
        except MemoryError:
            return MemoryError
        except:
            return None
        finally:
            oZipContent.close()
            oZipfile.close()

    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except MemoryError:
        return MemoryError
    except:
        return None
    finally:
        f.close()

def Data2File(data, filename):
    try:
        f = open(filename, 'wb')
    except:
        return False
    try:
        f.write(data)
    except:
        return False
    finally:
        f.close()
    return True

def SearchASCIIStrings(data, MIN_LENGTH = 5):
    dStrings = {}
    iStringStart = -1
    size = len(data)

    for iter in range(size):
        if data[iter] >= '\x20' and data[iter] <= '\x7F':
            if iStringStart == -1:
                iStringStart = iter
            elif iter + 1 == size and iter - iStringStart + 1 >= MIN_LENGTH:
                dStrings[iter] = data[iStringStart:iter + 1]
        elif iStringStart != -1:
            if iter - iStringStart >= MIN_LENGTH:
                dStrings[iter] = data[iStringStart:iter]
            iStringStart = -1
    return dStrings

def DumpBytes(memory, baseAddress, WIDTH=16):
    lineHex = ''
    lineASCII = ''
    for iter in range(len(memory)):
        lineHex += '%02X ' % ord(memory[iter])
        if memory[iter] >= '\x20' and memory[iter] <= '\x7F':
            lineASCII += memory[iter]
        else:
            lineASCII += '.'
        if iter % WIDTH == WIDTH - 1:
            print(' %08X: %s %s' % (baseAddress + iter / WIDTH * WIDTH, lineHex, lineASCII))
            lineHex = ''
            lineASCII = ''
    if lineHex != '':
        lineHex += ' ' * (48 - len(lineHex))
        print(' %08X: %s %s' % (baseAddress + iter / WIDTH * WIDTH, lineHex, lineASCII))

def FindAllStrings(string, search):
    indices = []
    index = string.find(search)
    while index >= 0:
        indices.append(index)
        index = string.find(search, index + 1)
    return indices

def iif(booleanExpression, valueTrue, valueFalse):
    if booleanExpression:
        return valueTrue
    else:
        return valueFalse

def cn(value, format = None):
    if value == None:
        return 'Not found'
    elif format == None:
        return value
    else:
        return format % value

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

def LogLine(line):
    print('%s: %s' % (Timestamp(), line))

class cBufferFile():
    def __init__(self, filename, buffersize, bufferoverlapsize):
        self.filename = filename
        self.buffersize = buffersize
        self.bufferoverlapsize = bufferoverlapsize
        self.fIn = None
        self.error = False
        self.index = None
        self.buffer = None
        self.filesize = os.path.getsize(self.filename)
        self.bytesread = 0

    def Read(self):
        if self.fIn == None:
            try:
                self.fIn = open(self.filename, 'rb')
            except:
                self.error = True
                return False

        if self.index == None:
            self.index = 0
            try:
                self.buffer = self.fIn.read(self.buffersize + self.bufferoverlapsize)
                self.bytesread += len(self.buffer)
            except MemoryError:
                self.fIn.close()
                self.error = MemoryError
                return False
            except:
                self.fIn.close()
                self.error = True
                return False
            if self.buffer == '':
                self.fIn.close()
                return False
            else:
                return True
        else:
            self.buffer = self.buffer[-self.bufferoverlapsize:]
            try:
                tempBuffer = self.fIn.read(self.buffersize)
                if tempBuffer == '':
                    self.fIn.close()
                    return False
                self.buffer += tempBuffer
                self.index += self.buffersize
                self.bytesread += len(tempBuffer)
                return True
            except MemoryError:
                self.fIn.close()
                self.error = MemoryError
                return False
            except:
                self.fIn.close()
                self.error = True
                return False

    def Progress(self):
        return int(float(self.bytesread) / float(self.filesize) * 100.0)
