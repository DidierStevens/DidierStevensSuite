#!/usr/bin/python

"""file2vbscript V0.3

tool to create a VBScript containing an embedded (executable) file

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/02/01: V0.1
  2008/03/09: V0.2 Splitting for Office
  2008/03/10: Refactoring
  2008/03/14: V0.3 LoadLibrary

"""

from optparse import OptionParser

def Main():
    """Create a VBScript containing an embedded (executable) file
    """
    
    parser = OptionParser(usage="usage: %prog [options] infile outfile.vbs", version="%prog 0.3")
    parser.add_option("-f", "--filename", default="file.exe", help="use FILENAME as the name of the file to dump")
    parser.add_option("-n", "--norun", action="store_true", default=False, help="don't execute the dumped file")
    parser.add_option("-o", "--office", action="store_true", default=False, help="create a VBScript for Microsoft Office")
    parser.add_option("-l", "--loadlibrary", action="store_true", default=False, help="generate a script that will create and load the file infile as a DLL")
    (options, args) = parser.parse_args()
    
    if len(args) != 2:
        parser.print_help()
        print ""
        print "  Use this program to generate a VBscript outfile.vbs that will create"
        print "  file infile and execute it."
        print "  Source code put in the public domain by Didier Stevens, no Copyright"
        print "  Use at your own risk"
        print "  https://DidierStevens.com"
    
    else:
        infile = open(args[0], 'rb')
        outfile = open(args[1], 'w')
    
        if options.loadlibrary:
            print >> outfile, "Private Declare Function LoadLibrary Lib \"KERNEL32\" Alias \"LoadLibraryA\" (ByVal strFileName As String) As Long"
            print >> outfile, "Private Declare Function FreeLibrary Lib \"KERNEL32\" (ByVal hLibrary As Long) As Long"
            print >> outfile, ""

        if not options.office:
            print >> outfile, "DoIt"
            print >> outfile, ""

        if options.loadlibrary:
            print >> outfile, "Sub DoIt()"
            print >> outfile, "\tDim hLibrary"
            print >> outfile, "\tDim strFile"
            print >> outfile, ""
            print >> outfile, "\tstrFile = TempFilename"
            print >> outfile, "\tDumpFile strFile"
            print >> outfile, "\thLibrary = LoadLibrary(strFile)"
            print >> outfile, "\tFreeLibrary hLibrary"
            print >> outfile, "\tDeleteFile strFile"
            print >> outfile, "End Sub"
            print >> outfile, ""
        else:
            print >> outfile, "Sub DoIt()"
            print >> outfile, "\tDim strFile"
            print >> outfile, ""
            print >> outfile, "\tstrFile = \"%s\"" % options.filename
            print >> outfile, "\tDumpFile strFile"
            if not options.norun:
                print >> outfile, "\tRunFile strFile"
            print >> outfile, "End Sub"
            print >> outfile, ""

        if options.loadlibrary:
            print >> outfile, "Function TempFilename()"
            print >> outfile, "\tDim objFSO"
            print >> outfile, ""
            print >> outfile, "\tSet objFSO = CreateObject(\"Scripting.FileSystemObject\")"
            print >> outfile, "\tTempFilename = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetTempName)"
            print >> outfile, "End Function"
            print >> outfile, ""
            print >> outfile, "Sub DeleteFile(strFilename)"
            print >> outfile, "\tDim objFSO"
            print >> outfile, ""
            print >> outfile, "\tSet objFSO = CreateObject(\"Scripting.FileSystemObject\")"
            print >> outfile, "\tobjFSO.DeleteFile strFilename"
            print >> outfile, "End Sub"
        else:
            print >> outfile, "Sub RunFile(strFilename)"
            print >> outfile, "\tDim sh"
            print >> outfile, ""
            print >> outfile, "\tSet sh = CreateObject(\"WScript.Shell\")"
            print >> outfile, "\tsh.Run strFilename"
            print >> outfile, "End Sub"
        print >> outfile, ""

        print >> outfile, "Sub WriteBytes(objFile, strBytes)"
        print >> outfile, "\tDim aNumbers"
        print >> outfile, "\tDim iIter"
        print >> outfile, ""
        print >> outfile, "\taNumbers = split(strBytes)"
        print >> outfile, "\tfor iIter = lbound(aNumbers) to ubound(aNumbers)"
        print >> outfile, "\t\tobjFile.Write Chr(aNumbers(iIter))"
        print >> outfile, "\tnext"
        print >> outfile, "End Sub"
        print >> outfile, ""
        
        countLine = 0
        countSubs = 1
        line = ""
        
        print >> outfile, "Sub DumpFile%d(objFile)" % countSubs
            
        while True:
            inbyte = infile.read(1)
            if not inbyte:
                break
            if len(line) > 0:
                line = line + " "
            line = line + "%d" % ord(inbyte)
            if len(line) > 80:
                print >> outfile, "\tWriteBytes objFile, \"%s\"" % line
                line = ""
                countLine += 1
                if options.office and countLine > 99:
                    countLine = 0
                    print >> outfile, "End Sub"
                    print >> outfile, ""
                    countSubs += 1
                    print >> outfile, "Sub DumpFile%d(objFile)" % countSubs
    
        if len(line) > 0:
            print >> outfile, "\tWriteBytes objFile, \"%s\"" % line
            
        print >> outfile, "End Sub"
        print >> outfile, ""
        print >> outfile, "Sub DumpFile(strFilename)"
        print >> outfile, "\tDim objFSO"
        print >> outfile, "\tDim objFile"
        print >> outfile, ""
        print >> outfile, "\tSet objFSO = CreateObject(\"Scripting.FileSystemObject\")"
        print >> outfile, "\tSet objFile = objFSO.OpenTextFile(strFilename, 2, true)"
        for iIter in range(1, countSubs+1):
            print >> outfile, "\tDumpFile%d objFile" % iIter
        print >> outfile, "\tobjFile.Close"
        print >> outfile, "End Sub"
    
        infile.close()
        outfile.close()

Main()
