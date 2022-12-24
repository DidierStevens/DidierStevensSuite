#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Use pydivert to redirect DNS queries to the machine itself, and make replies appear to come from the DNS server.'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2022/12/21'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2022/12/05: start
  2022/12/11: refactoring
  2022/12/12: wrote man page

Todo:

"""

import sys
import argparse
import textwrap
try:
    import pydivert
except ImportError:
    print('module pydivert is not installed, please install it (with pip, for example)')
    sys.exit()

def PrintManual():
    manual = r'''
Manual:

This tool uses pydivert/windivert to redirect IPv4 DNS traffic.
The tool doesn't take arguments.
You have to run this tool with an account with admin rights.

When started, it listens for IPv4 UDP packets with source and/or destination port equal to 53.
When this tools processes its first UDP packet with destination port 53, it considers the source address of this packet as the DNS client's IPv4 address (e.g., the Windows machine this tool is running on) and the destination address to be the IPv4 address of the DNS server used by the client.
From then on, all IPv4 UDP packets with source or destination port 53 (including that first packet) are altered by the tool.
All IPv4 UDP packets with destination port 53, have their destination address changed to the IPv4 address of the client.
All IPv4 UDP packets with source port 53, have their source address changed to the IPv4 address of the DNS server.

Example. A Windows machine has IPv4 address 192.168.0.10 and uses DNS address 8.8.8.8.
When this tool is started, it looks for all IPv4 UDP packets with source port and/or destination port equal to 53.
From the first IPv4 UDP packet with destination port 53 is processes, it takes the destination address (8.8.8.8) and the source address (192.168.0.10).
It alters this packet destination address (and all subsequent IPv4 UDP packets with destination port 53) to 192.168.0.10)
And it alters the source address from all IPv4 UDP packets with source port 53 to 8.8.8.8.

By doing this, IPv4 UDP traffic with destination port 53 is redirected to the client itself.
Where a DNS server can be running, like dnsresolver.py, that handles these incoming packets, and sends back replies.
And these replies are altered (source address set to DNS server's IPv4 address), so that it looks like the replies come from the normal DNS server, and not dnsresolver.py

Caveats:
* This tool does not handle IPv6.
* This tool does not check if the UDP packets to and/or from port 53 are actual DNS packets.
* This tool ignores DNS traffic over TCP.
* This tool does not handle queries to multiple DNS servers (different IPv4 addresses) correctly.

I might address these issues in upcoming releases.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

def DnsPyDivert():
    clientIP = None
    clientDNS = None

    with pydivert.WinDivert('ip and (udp.DstPort == 53 or udp.SrcPort == 53)') as oWinDivert:
        print('dns-pydivert started')
        for oPacket in oWinDivert:
            if clientDNS == None and oPacket.dst_port == 53:
                clientIP = oPacket.src_addr
                clientDNS = oPacket.dst_addr
                print('clientIP: %s' % clientIP)
                print('clientDNS: %s' % clientDNS)
            if oPacket.dst_addr == clientDNS and oPacket.dst_port == 53:
                print('Packet to   clientDNS: changing dst_addr %s -> %s' % (oPacket.dst_addr, clientIP))
                oPacket.dst_addr = clientIP
            if oPacket.src_addr == clientIP and oPacket.src_port == 53:
                print('Packet from clientDNS: changing src_addr %s -> %s' % (oPacket.src_addr, clientDNS))
                oPacket.src_addr = clientDNS
            oWinDivert.send(oPacket, True)

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oArgumentParser = argparse.ArgumentParser(description=__description__ + moredesc)
    oArgumentParser.add_argument('-m', '--man', action='store_true', default=False, help='Print manual')
    oArgumentParser.add_argument('--version', action='version', version=__version__)
    args = oArgumentParser.parse_args()

    if args.man:
        oArgumentParser.print_help()
        PrintManual()
        return

    DnsPyDivert()

if __name__ == '__main__':
    Main()
