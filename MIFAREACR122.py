#!/usr/bin/env python

"""

MIFARE RFID tag read/write utility for ACS ACR122 writer

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2009/02/17: start
  2009/02/18: writefile
  2009/02/19: shellcode execution

Todo:
  - support other types than MIFARE 1K tags
"""

__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2009/02/19'

import smartcard.System
import smartcard.util
import smartcard.CardConnection
import optparse

DEFAULT_KEYA = 'FFFFFFFFFFFF'

def ReadBinaryFile(name):
    try:
        fBinary = open(name, 'rb')
    except:
        return None
    try:
        return fBinary.read()
    except:
        return None
    finally:
        fBinary.close()
    return None

def WriteBinaryFile(name, content):
    try:
        fBinary = open(name, 'wb')
    except:
        return False
    try:
        fBinary.write(content)
    except:
        return False
    finally:
        fBinary.close()
    return True

class cMIFARE:
    def __init__(self):
        self.smartCardReader = self.GetSmartCardReader()
        if str(self.smartCardReader) == '':
            print 'No ACS ACR122 reader found'
            exit()
        print 'Reader: %s' % self.smartCardReader
        self.KeyBlockNumber = None

    def GetSmartCardReader(self):
        """
           If only one reader connected, return that reader.
           If more than one reader is connected, return the first reader with the string ACR122"""
           
        readers = smartcard.System.readers()
        if len(readers) == 1:
            return readers[0]
        elif len(readers) == 0:
            return ''
        else:
            for r in readers:
                if str(r).upper().find('ACR122') > -1:
                    return r
            print 'Error selecting reader, readers: %s' % readers
            return ''

    def TransmitCommand(self, command):
        data, sw1, sw2 = self.connection.transmit(command, protocol=smartcard.CardConnection.CardConnection.T1_protocol)
        if sw1 != 0x90 or sw2 != 0x00:
            print 'sw1, sw2 = %02x %02x' % (sw1, sw2)
            print 'data     = ' + smartcard.util.toHexString(data)
            return None
        else:
            return data

    def Connect(self):
        self.connection = self.smartCardReader.createConnection()
        self.connection.connect()

    def Disconnect(self):
        self.connection.disconnect()

    def WaitForTag(self):
        self.connection = self.smartCardReader.createConnection()
        loop = True
        while loop:
            try:
                self.connection.connect()
                loop = False
            except:
                pass
        self.connection.disconnect()

    def Poll(self):
        data = self.TransmitCommand(smartcard.util.toBytes('FF00000004D44A0100'))
        if data != None:
            self.tag_number = data[2]
            self.target_number = data[3]
            self.sens_res = data[4:6]
            self.sel_res = data[6]
            self.uid_length = data[7]
            self.uid_value = data[8:]
            print 'MIFARE type: %02x' % self.sel_res
            print 'UID: ' + smartcard.util.toHexString(self.uid_value)
    
    def KeyA(self, block, key=DEFAULT_KEYA):
        APDU = smartcard.util.toBytes('FF000000')
        APDU.append(11 + self.uid_length)
        APDU += smartcard.util.toBytes('D440')
        APDU.append(self.target_number)
        APDU.append(0x60) # 0x61 for key B
        APDU.append(block)
        APDU += smartcard.util.toBytes(key)
        APDU += self.uid_value
        data = self.TransmitCommand(APDU)
        if data != None:
            if data[2] != 0:
                print 'Error:'
                print data
            return data[2]
        else:
            print 'Error:'
            return -1
            
    def PrepareKeyA(self, block, key):
        if self.KeyBlockNumber == None:
            self.KeyA(block, key)
            self.KeyBlockNumber = block
        elif self.KeyBlockNumber / 4 != block / 4:
            self.KeyA(block, key)
            self.KeyBlockNumber = block

    def ReadBlock(self, block, key=DEFAULT_KEYA):
        self.PrepareKeyA(block, key)
        APDU = smartcard.util.toBytes('FF00000005D440')
        APDU.append(self.target_number)
        APDU.append(0x30)
        APDU.append(block)
        data = self.TransmitCommand(APDU)
        if data != None:
            print 'Block %02X: %s' % (block, smartcard.util.toHexString(data[3:]))
            return data[3:]
        else:
            return []
    
    def WriteBlock(self, block, values, key=DEFAULT_KEYA):
        self.PrepareKeyA(block, key)
        APDU = smartcard.util.toBytes('FF00000015D440')
        APDU.append(self.target_number)
        APDU.append(0xA0)
        APDU.append(block)
        APDU += values
        data = self.TransmitCommand(APDU)
        if data != None:
            if data[2] != 0:
                print 'Error:'
                print data
            return data[2]
        else:
            print 'Error:'
            return -1
    
    def ID(self):
        self.Connect()
        self.Poll()
        self.Disconnect()

    def Dump(self):
        self.Connect()

        data = []
        
        self.Poll()
        for block in range(1024 / 16): # MIFARE 1K
            data += self.ReadBlock(block)
        
        self.Disconnect()

        return data

    def DumpWritable(self):
        self.Connect()

        data = []
        
        self.Poll()
        for block in range(1, 1024 / 16): # MIFARE 1K
            if (block+1) % 4 != 0:
                data += self.ReadBlock(block)
        
        self.Disconnect()
        
        return data

    def WriteSequence(self, sequence, key=DEFAULT_KEYA):
        self.Connect()

        self.Poll()
        rest = sequence
        for block in range(1, 1024 / 16): # MIFARE 1K
            if (block+1) % 4 != 0:
                if len(rest) >= 16:
                    values = rest[0:16]
                    rest = rest[16:]
                else:
                    values = rest
                    rest = []
                    if len(values) > 0:
                        values += [0] * (16 - len(values))
                if len(values) > 0:
                    if (self.WriteBlock(block, values, key) == 0):
                        print 'Write block %02X OK' % block
        
        self.Disconnect()
        
    def Wipe(self):
        self.WriteSequence([0] * (16 * (16 * 3 - 1)))
#        self.WriteSequence([i % 0x100 for i in range(16 * (16 * 3 - 1))])

def ExecuteShellcode(shellcode):
    import ctypes
    lMemory = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x1000|0x2000, 0x40)
    lResult = ctypes.windll.kernel32.WriteProcessMemory(-1, lMemory, shellcode, len(shellcode), 0)
    lResult = ctypes.windll.kernel32.CreateThread(0, 0, lMemory, 0, 0, 0)
    return lResult

def Usage(oParser):
    oParser.print_help()
    print
    print '  MIFARE RFID tag read/write utility for ACS ACR122 writer'
    print '  Source code put in the public domain by Didier Stevens, no Copyright'
    print '  Use at your own risk'
    print '  https://DidierStevens.com'
    return

def Main():
    usageCommands = """\nCommands:
  id: display tag id
  dump: hexdump all tag blocks
  dumpwritable: hexdump all writable tag blocks
  wipe: overwrite all writable tag blocks with zeroes
  print: display all writable tag blocks
  read file: read all writable tag blocks and store in file
  write file: write content of file to all writable tag blocks
  shellcode: execute shellcode read from tag"""
    oParser = optparse.OptionParser(usage='usage: %prog command [file]' + usageCommands, version='%prog ' + __version__)
    (options, args) = oParser.parse_args()

    if len(args) == 0 or len(args) > 2:
        Usage(oParser)
        return
    command = args[0].lower()
    if len(args) == 2:
        filename = args[1]
    else:
        filename = None
    
    if command == 'id' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        oMIFARE.ID()

    elif command == 'dump' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        oMIFARE.Dump()

    elif command == 'dumpwritable' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        oMIFARE.DumpWritable()

    elif command == 'wipe' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        oMIFARE.Dump()
        oMIFARE.Wipe()
        oMIFARE.DumpWritable()

    elif command == 'print' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        data = oMIFARE.DumpWritable()
        print ''.join([chr(i) for i in data])

    elif command == 'read' and filename != None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        data = oMIFARE.DumpWritable()
        WriteBinaryFile(filename, ''.join([chr(i) for i in data]))

    elif command == 'write' and filename != None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        oMIFARE.WriteSequence([ord(c) for c in ReadBinaryFile(filename)])
        oMIFARE.DumpWritable()

    elif command == 'shellcode' and filename == None:
        oMIFARE = cMIFARE()
        oMIFARE.WaitForTag()
        data = oMIFARE.DumpWritable()
        ExecuteShellcode(''.join([chr(i) for i in data]))
        raw_input('Press ENTER when done: ')

    else:
        Usage(oParser)

if __name__ == '__main__':
    Main()
