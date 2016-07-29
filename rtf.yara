/*
  Version 0.0.1 2016/07/24
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  These are YARA rules to detect shellcode, translated from XORSearch's wildcard rules,
  which themselves were developed based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

  Shortcomings, or todo's ;-) :

  History:
    2015/09/15: start
    2016/07/24: RTF_ListView2_CLSID
*/

rule includepicture_http
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = "INCLUDEPICTURE"
        $a2 = "http" nocase
    condition:
        $a1 and $a2
}

// https://securelist.com/analysis/publications/37158/the-curious-case-of-a-cve-2012-0158-exploit/
rule RTF_ListView2_CLSID
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {4B F0 D1 BD 8B 85 D1 11 B1 6A 00 C0 F0 28 36 28}
    condition:
        any of them
}
