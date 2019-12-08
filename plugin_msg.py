#!/usr/bin/env python

__description__ = 'MSG plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2019/11/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/12/16: start
  2017/12/17: 0.0.2 added options -d and -a
  2017/12/30: removed option -a (becomes default) and -d; and added option -n
  2018/07/14: 0.0.3 added option -k
  2019/11/04: 0.0.4 added tag 1009

Todo:
"""

import struct
import re
import optparse

class cMSG(cPluginParent):
    macroOnly = False
    indexQuiet = True
    name = 'MSG plugin'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        #http://www.fileformat.info/format/outlookmsg/
        dCodes = {
          '001A': 'Message class',
          '0037': 'Subject',
          '003D': 'Subject prefix',
          '0040': 'Received by name',
          '0042': 'Sent repr name',
          '0044': 'Rcvd repr name',
          '004D': 'Org author name',
          '0050': 'Reply rcipnt names',
          '005A': 'Org sender name',
          '0064': 'Sent repr adrtype',
          '0065': 'Sent repr email',
          '0070': 'Topic',
          '0075': 'Rcvd by adrtype',
          '0076': 'Rcvd by email',
          '0077': 'Repr adrtype',
          '0078': 'Repr email',
          '007D': 'Message header',
          '0C1A': 'Sender name',
          '0C1E': 'Sender adr type',
          '0C1F': 'Sender email',
          '0E02': 'Display BCC',
          '0E03': 'Display CC',
          '0E04': 'Display To',
          '0E1D': 'Subject (normalized)',
          '0E28': 'Recvd account1(?)',
          '0E29': 'Recvd account2(?)',
          '1000': 'Message body',
          '1008': 'RTF sync body tag',
          '1009': 'RTF Compressed',
          '1035': 'Message ID (?)',
          '1046': 'Sender email(?)',
          '3001': 'Display name',
          '3002': 'Address type',
          '3003': 'Email address',
          '39FE': '7-bit email (?)',
          '39FF': '7-bit display name',
          '3701': 'Attachment data',
          '3703': 'Attach extension',
          '3704': 'Attach filename',
          '3707': 'Attach long filename',
          '370E': 'Attach mime tag',
          '3712': 'Attach ID (?)',
          '3A00': 'Account',
          '3A02': 'Callback phone no',
          '3A05': 'Generation',
          '3A06': 'Given name',
          '3A08': 'Business phone',
          '3A09': 'Home phone',
          '3A0A': 'Initials',
          '3A0B': 'Keyword',
          '3A0C': 'Language',
          '3A0D': 'Location',
          '3A11': 'Surname',
          '3A15': 'Postal address',
          '3A16': 'Company name',
          '3A17': 'Title',
          '3A18': 'Department',
          '3A19': 'Office location',
          '3A1A': 'Primary phone',
          '3A1B': 'Business phone 2',
          '3A1C': 'Mobile phone',
          '3A1D': 'Radio phone no',
          '3A1E': 'Car phone no',
          '3A1F': 'Other phone',
          '3A20': 'Transmit dispname',
          '3A21': 'Pager',
          '3A22': 'User certificate',
          '3A23': 'Primary Fax',
          '3A24': 'Business Fax',
          '3A25': 'Home Fax',
          '3A26': 'Country',
          '3A27': 'Locality',
          '3A28': 'State/Province',
          '3A29': 'Street address',
          '3A2A': 'Postal Code',
          '3A2B': 'Post Office Box',
          '3A2C': 'Telex',
          '3A2D': 'ISDN',
          '3A2E': 'Assistant phone',
          '3A2F': 'Home phone 2',
          '3A30': 'Assistant',
          '3A44': 'Middle name',
          '3A45': 'Dispname prefix',
          '3A46': 'Profession',
          '3A48': 'Spouse name',
          '3A4B': 'TTYTTD radio phone',
          '3A4C': 'FTP site',
          '3A4E': 'Manager name',
          '3A4F': 'Nickname',
          '3A51': 'Business homepage',
          '3A57': 'Company main phone',
          '3A58': 'Childrens names',
          '3A59': 'Home City',
          '3A5A': 'Home Country',
          '3A5B': 'Home Postal Code',
          '3A5C': 'Home State/Provnce',
          '3A5D': 'Home Street',
          '3A5F': 'Other adr City',
          '3A60': 'Other adr Country',
          '3A61': 'Other adr PostCode',
          '3A62': 'Other adr Province',
          '3A63': 'Other adr Street',
          '3A64': 'Other adr PO box',
          '3FF7': 'Server   (?)',
          '3FF8': 'Creator1 (?)',
          '3FFA': 'Creator2 (?)',
          '3FFC': 'To email (?)',
          '403D': 'To adrtype(?)',
          '403E': 'To email (?)',
          '5FF6': 'To       (?)'
        }

        dTypes = {'001E': 'ASC', '001F': 'UNI', '0102': 'BIN'}

        oParser = optparse.OptionParser()
        oParser.add_option('-n', '--nodecode', action='store_true', default=False, help='Do not decode data')
        oParser.add_option('-k', '--known', action='store_true', default=False, help='Only display known hexcodes')
        (options, args) = oParser.parse_args(self.options.split(' '))

        self.ran = True
        oMatch = re.search('_[0-9A-F]{8}', self.streamname[-1])
        if oMatch != None:
            hexcode = oMatch.group()[1:5]
            hextype = oMatch.group()[5:]
            if hextype == '001F':
                decoded = self.stream.decode('utf16')
            elif hextype == '0102':
                decoded = repr(self.stream)
            else:
                decoded = ''
            line = '%s %s: %s %s' % (hexcode, hextype, dTypes.get(hextype, '?  '), dCodes.get(hexcode, '?'))
            if options.nodecode:
                pass
            else:
                line = (line + ' ' * 40)[0:40] + ' ' + decoded[0:40]
            if not options.known or options.known and hexcode in dCodes:
                result.append(line)
        
        return result

AddPlugin(cMSG)
