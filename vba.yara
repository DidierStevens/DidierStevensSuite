/*
  Version 0.0.2 2021/01/22
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  These are YARA rules to detect VBA code that might be malware.
  They are designed to be used with oledump.py.
  To use them with the YARA tool, you have to define variable VBA: yara32 -d VBA=1 vba.yara .

  Shortcomings, or todo's ;-) :

  History:
    2017/03/05: start
    2021/01/22: 0.0.2 update description
*/

rule VBA_Autorun
{
    strings:
        $a = "AutoExec" nocase fullword
        $b = "AutoOpen" nocase fullword
        $c = "DocumentOpen" nocase fullword
        $d = "AutoExit" nocase fullword
        $e = "AutoClose" nocase fullword
        $f = "Document_Close" nocase fullword
        $g = "DocumentBeforeClose" nocase fullword
        $h = "Document_Open" nocase fullword
        $i = "Document_BeforeClose" nocase fullword
        $j = "Auto_Open" nocase fullword
        $k = "Workbook_Open" nocase fullword
        $l = "Workbook_Activate" nocase fullword
        $m = "Auto_Close" nocase fullword
        $n = "Workbook_Close" nocase fullword
    condition:
        VBA and any of ($*)
}

rule VBA_Object
{
    strings:
        $a = "CreateObject" nocase fullword
        $b = "GetObject" nocase fullword
    condition:
        VBA and any of ($*)
}

rule VBA_Declare
{
    strings:
        $a = "Declare" nocase fullword
    condition:
        VBA and any of ($*)
}

rule VBA_CallByName
{
    strings:
        $a = "CallByName" nocase fullword
    condition:
        VBA and any of ($*)
}

rule VBA_Shell
{
    strings:
        $a = ".Run" nocase
        $b = "Shell" nocase fullword
    condition:
        VBA and any of ($*)
}

