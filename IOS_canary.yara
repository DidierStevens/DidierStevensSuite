/*
  Version 0.0.1 2015/02/22
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :

  History:
    2015/02/22: start
*/

rule IOS_canary
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Search for a Cisco IOS canary value"
        method = "Find canary sequence FD0110DF"
    strings:
        $canary = {FD 01 10 DF}
    condition:
        $canary
}