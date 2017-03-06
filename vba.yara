/*
  Version 0.0.1 2017/03/05
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  These are YARA rules to detect VBA code that might be malware.

  Shortcomings, or todo's ;-) :

  History:
    2017/03/05: start
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

