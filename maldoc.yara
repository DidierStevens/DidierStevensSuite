/*
  Version 0.0.2 2014/12/16
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  These are YARA rules to detect shellcode, translated from XORSearch's wildcard rules,
  which themselves were developed based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

  Shortcomings, or todo's ;-) :
    Remaining XORSearch wildcard rules:
      GetEIP method 2:10:EB(J;1)E8(J;4)(B;01011???)
      GetEIP method 3:10:E9(J;4)E8(J;4)(B;01011???)

  History:
    2014/12/15: start
    2014/12/16: extra documentation
*/

/*
XORSearch wildcard rule(s):
    API Hashing:10:AC84C07407C1CF0D01C7EBF481FF
    API Hashing bis:10:AC84C07407C1CF0701C7EBF481FF
*/
rule maldoc_API_hashing
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Function prolog signature:10:558BEC83C4
    Function prolog signature:10:558BEC81EC
    Function prolog signature:10:558BECEB
    Function prolog signature:10:558BECE8
    Function prolog signature:10:558BECE9
*/
rule maldoc_function_prolog_signature
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Structured exception handling :10:648B(B;00???101)00000000
    Structured exception handling bis:10:64A100000000
*/
rule maldoc_structured_exception_handling
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 00 00 00 00}
        $a2 = {64 A1 00 00 00 00}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Indirect function call:10:FF75(B;A???????)FF55(B;A???????)
*/
rule maldoc_indirect_function_call_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

/*
XORSearch wildcard rule(s):
    Indirect function call bis:10:FFB5(B;A???????)(B;B???????)(B;C???????)(B;D???????)FF95(B;A???????)(B;B???????)(B;C???????)(B;D???????)
*/
rule maldoc_indirect_function_call_2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

/*
XORSearch wildcard rule(s):
    Indirect function call tris:10:FFB7(B;????????)(B;????????)(B;????????)(B;????????)FF57(B;????????)
*/
rule maldoc_indirect_function_call_3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

/*
XORSearch wildcard rule(s):
    Find kernel32 base method 1:10:648B(B;00???101)30000000
    Find kernel32 base method 1bis:10:64A130000000
*/
rule maldoc_find_kernel32_base_method_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Find kernel32 base method 2:10:31(B;11A??A??)(B;10100A??)30648B(B;00B??A??)
*/
rule maldoc_find_kernel32_base_method_2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

/*
XORSearch wildcard rule(s):
    Find kernel32 base method 3:10:6830000000(B;01011A??)648B(B;00B??A??)
*/
rule maldoc_find_kernel32_base_method_3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

/*
XORSearch wildcard rule(s):
    GetEIP method 1:10:E800000000(B;01011???)
*/
rule maldoc_getEIP_method_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}

/*
XORSearch wildcard rule(s):
    GetEIP method 4 FLDZ/FSTENV [esp-12]:10:D9EED97424F4(B;01011???)
    GetEIP method 4:10:D9EE9BD97424F4(B;01011???)
*/
rule maldoc_getEIP_method_4
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
        $a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    OLE file magic number:10:D0CF11E0
*/
rule maldoc_OLE_file_magic_number
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}

/*
XORSearch wildcard rule(s):
    Suspicious strings:2:str=UrlDownloadToFile
    Suspicious strings:2:str=GetTempPath
    Suspicious strings:2:str=GetWindowsDirectory
    Suspicious strings:2:str=GetSystemDirectory
    Suspicious strings:2:str=WinExec
    Suspicious strings:2:str=ShellExecute
    Suspicious strings:2:str=IsBadReadPtr
    Suspicious strings:2:str=IsBadWritePtr
    Suspicious strings:2:str=CreateFile
    Suspicious strings:2:str=CloseHandle
    Suspicious strings:2:str=ReadFile
    Suspicious strings:2:str=WriteFile
    Suspicious strings:2:str=SetFilePointer
    Suspicious strings:2:str=VirtualAlloc
    Suspicious strings:2:str=GetProcAddr
    Suspicious strings:2:str=LoadLibrary
*/
rule maldoc_suspicious_strings
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a01 = "CloseHandle"
        $a02 = "CreateFile"
        $a03 = "GetProcAddr"
        $a04 = "GetSystemDirectory"
        $a05 = "GetTempPath"
        $a06 = "GetWindowsDirectory"
        $a07 = "IsBadReadPtr"
        $a08 = "IsBadWritePtr"
        $a09 = "LoadLibrary"
        $a10 = "ReadFile"
        $a11 = "SetFilePointer"
        $a12 = "ShellExecute"
        $a13 = "UrlDownloadToFile"
        $a14 = "VirtualAlloc"
        $a15 = "WinExec"
        $a16 = "WriteFile"
    condition:
        any of them
}
