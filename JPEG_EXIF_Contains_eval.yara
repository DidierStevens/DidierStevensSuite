/*
  Version 0.0.3 2015/02/15
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :
    Constant 0x06 in the condition is the minimum length of the string matched by regex $b.
    Ideally, this should be an expression and not a constant, for example len($d).

  History:
    2014/12/23: start
    2015/01/01: continued
    2015/01/11: changed regex to \W
    2015/02/15: replaced regex \W with \b (available in YARA 3.3.0)
*/

rule JPEG_EXIF_Contains_eval
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect eval function inside JPG EXIF header (http://blog.sucuri.net/2013/07/malware-hidden-inside-jpg-exif-headers.html)"
        method = "Detect JPEG file and EXIF header ($a) and eval function ($b) inside EXIF data"
    strings:
        $a = {FF E1 ?? ?? 45 78 69 66 00}
        $b = /\beval\s*\(/
    condition:
        uint16be(0x00) == 0xFFD8 and $a and $b in (@a + 0x12 .. @a + 0x02 + uint16be(@a + 0x02) - 0x06)
}
