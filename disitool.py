#!/usr/bin/env python

"""
tool to manipulate digital signatures in PE files

commands:
- delete signed-file unsigned-file
- copy signed-source-file unsigned-file signed-file
- extract signed-file signature
- add signature unsigned-file signed-file
- inject [--paddata] signed-source-file data-file signed-destination-file

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
 2007/12/21: added arguments
 2008/01/09: code review
 2008/03/26: added checksum correction
 2009/01/17: V0.3 added inject, requested by H D Moore
 2009/01/18: --paddata option
 2020/11/27: 0.4 Python 3

requires pefile:
 http://code.google.com/p/pefile/
 to install: setup.py install
"""

import optparse
import pefile
from struct import *

__author__ = 'Didier Stevens (https://DidierStevens.com)'
__version__ = '0.4'
__date__ = '2020/11/27'

def Usage():
    """Displays the usage of this tool
    """
    
    print('Usage: disitool command [options] file ...')
    print('  disitool V%s %s, tool to manipulate digital signatures in PE files' % (__version__, __date__))
    print('  commands:')
    print('  - delete signed-file unsigned-file')
    print('  - copy signed-source-file unsigned-file signed-file')
    print('  - extract signed-file signature')
    print('  - add signature unsigned-file signed-file')
    print('  - inject [--paddata] signed-source-file data-file signed-destination-file')
    print('  Source code put in the public domain by Didier Stevens, no Copyright')
    print('  Use at your own risk')
    print('  https://DidierStevens.com')

def DeleteDigitalSignature(SignedFile, UnsignedFile=None):
    """Deletes the digital signature from file SignedFile
       When UnsignedFile is not None, writes the modified file to UnsignedFile
       Returns the modified file as a PE file
    """
    
    pe = pefile.PE(SignedFile)
    
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0

    if address != 0:
        peUnsignedFile = pefile.PE(data=pe.write()[0:address])
    else:
        peUnsignedFile = pefile.PE(data=pe.write())
    
    peUnsignedFile.OPTIONAL_HEADER.CheckSum = peUnsignedFile.generate_checksum()
    
    new_file_data = peUnsignedFile.write()

    if UnsignedFile:
        f = open(UnsignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def CopyDigitalSignature(SignedSourceFile, UnsignedFile, SignedFile=None):
    """Extracts the digital signature from file SignedSourceFile and adds it to file UnsignedFile
       When SignedFile is not None, writes the modified file to SignedFile
       Returns the modified file as a PE file
    """
    
    peSignedSource =  pefile.PE(SignedSourceFile)
    
    address = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print('Error: source file not signed')
        return

    signature = peSignedSource.write()[address:]

    peUnsigned = DeleteDigitalSignature(UnsignedFile)
    
    peSignedFileTemp = pefile.PE(data=peUnsigned + signature)

    peSignedFileTemp.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = len(peUnsigned)
    peSignedFileTemp.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = size

    peSignedFile = pefile.PE(data=peSignedFileTemp.write())
    peSignedFile.OPTIONAL_HEADER.CheckSum = peSignedFile.generate_checksum()
    
    new_file_data = peSignedFile.write()
    
    if SignedFile:
        f = open(SignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def ExtractDigitalSignature(SignedFile, SignatureFile=None):
    """Extracts the digital signature from file SignedFile
       When SignatureFile is not None, writes the signature to SignatureFile
       Returns the signature
    """
    
    pe =  pefile.PE(SignedFile)

    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print('Error: source file not signed')
        return
    
    signature = pe.write()[address+8:]
    
    if SignatureFile:
        f = open(SignatureFile, 'wb+')
        f.write(signature)
        f.close()

    return signature

def AddDigitalSignature(SignatureFile, UnsignedFile, SignedFile=None):
    """Adds the digital signature from file SignatureFile to file UnsignedFile
       When SignedFile is not None, writes the modified file to SignedFile
       Returns the modified file as a PE file
    """
    
    f = open(SignatureFile, 'rb')
    signature = f.read()
    f.close()
    
    size = len(signature) + 8
    
    peUnsigned = DeleteDigitalSignature(UnsignedFile)
    
    peSignedFileTemp = pefile.PE(data=peUnsigned + pack('<I', size) + b'\x00\x02\x02\x00' + signature)

    peSignedFileTemp.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = len(peUnsigned)
    peSignedFileTemp.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = size

    peSignedFile = pefile.PE(data=peSignedFileTemp.write())
    peSignedFile.OPTIONAL_HEADER.CheckSum = peSignedFile.generate_checksum()

    new_file_data = peSignedFile.write()
    
    if SignedFile:
        f = open(SignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def InjectDataInSignedExecutable(SignedSourceFile, DataFile, SignedFile=None, paddata=False):
    """Inject data (DataFile) inside a signed executable (SignedSourceFile) without invalidating the signature
       The procedure is to append the data to the digital signature and increase the size of the digital signature
       When SignedFile is not None, writes the modified file to SignedFile
       Returns the modified file as a PE file
    """
    
    peSignedSource =  pefile.PE(SignedSourceFile)
    
    address = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = peSignedSource.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print('Error: source file not signed')
        return

    f = open(DataFile, 'rb')
    DataToInject = f.read()
    f.close()

    if len(DataToInject) % 8 != 0:
        if paddata:
            DataToInject = DataToInject + b'\x00' * (8 - (len(DataToInject) % 8))
            print('Info: padded the data to inject')
        else:
            print('Warning: the length of the data to inject is not a multiple of 8')
    
    signature = peSignedSource.write()[address:]

    peUnsigned = peSignedSource.write()[:address]

    peSignedFileTemp = pefile.PE(data=peUnsigned + signature + DataToInject)

    peSignedFileTemp.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = size + len(DataToInject)

    peSignedFile = pefile.PE(data=peSignedFileTemp.write())
    peSignedFile.OPTIONAL_HEADER.CheckSum = peSignedFile.generate_checksum()
    
    new_file_data = peSignedFile.write()
    
    if SignedFile:
        f = open(SignedFile, 'wb+')
        f.write(new_file_data)
        f.close()

    return new_file_data

def Main():
    """Parses the command line and executes the appropriate function
    """
    
    oParser = optparse.OptionParser(usage='usage: %prog [options] command files...', version='%prog ' + __version__)
    oParser.add_option('-p', '--paddata', action='store_true', default=False, help='pad data to a multiple of 8 bytes')
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        Usage()
    elif args[0] == 'delete':
        if len(args) == 3:
            DeleteDigitalSignature(args[1], args[2])
        else:
            Usage()
    elif args[0] == 'copy':
        if len(args) == 4:
            CopyDigitalSignature(args[1], args[2], args[3])
        else:
            Usage()
    elif args[0] == 'extract':
        if len(args) == 3:
            ExtractDigitalSignature(args[1], args[2])
        else:
            Usage()
    elif args[0] == 'add':
        if len(args) == 4:
            AddDigitalSignature(args[1], args[2], args[3])
        else:
            Usage()
    elif args[0] == 'inject':
        if len(args) == 4:
            InjectDataInSignedExecutable(args[1], args[2], args[3], options.paddata)
        else:
            Usage()
    else:
        Usage()

if __name__ == '__main__':
    Main()
