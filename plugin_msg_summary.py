#!/usr/bin/env python

__description__ = 'MSG summary plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2020/09/11'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/08/18: start
  2020/09/11: added body

Todo:
"""

import struct
import re
import optparse

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

class cAttachment(object):
    def __init__(self, name):
        self.name = name

class cMSG(cPluginParentOle):
    indexQuiet = True
    name = 'MSG summary plugin'

    def PreProcess(self):
        self.dAttachments = {}
        self.streamIndexCounter = 0

    def Process(self, name, stream):
        self.streamIndexCounter += 1
        found, number = StartsWithGetRemainder(name[0], '__attach_version1.0_#')
        if found:
            nameAttachment = name[0]
            numberAttachment = int(number)
            if not numberAttachment in self.dAttachments:
                self.dAttachments[numberAttachment] = cAttachment(nameAttachment)
                self.dAttachments[numberAttachment].number = numberAttachment
            found, code = StartsWithGetRemainder(name[1], '__substg1.0_')
            if found:
                if code == '37010102':
                    self.dAttachments[numberAttachment].data = stream
                    self.dAttachments[numberAttachment].streamIndex = self.streamIndexCounter
                elif code.startswith('3707'):
                    self.dAttachments[numberAttachment].longfilename = stream.decode('utf16') if code.endswith('001F') else stream.decode()
                elif code.startswith('370E'):
                    self.dAttachments[numberAttachment].mimetag = stream.decode('utf16') if code.endswith('001F') else stream.decode()

        found, code = StartsWithGetRemainder(name[0], '__substg1.0_')
        if found:
            if code.startswith('0037'):
                self.subject = stream.decode('utf16') if code.endswith('001F') else stream.decode()
            elif code.startswith('007D'):
                self.header = stream.decode('utf16') if code.endswith('001F') else stream.decode()
                self.headerStreamIndex = self.streamIndexCounter
                for line in self.header.split('\n'):
                    line = line.rstrip('\r')
                    found, value = StartsWithGetRemainder(line, 'Date: ')
                    if found:
                        self.date = value
                    found, value = StartsWithGetRemainder(line, 'To: ')
                    if found:
                        self.to = value
                    found, value = StartsWithGetRemainder(line, 'From: ')
                    if found:
                        self.from_ = value
            elif code.startswith('1000'):
                self.body = stream.decode('utf16') if code.endswith('001F') else stream.decode()
                self.bodyStreamIndex = self.streamIndexCounter

    def PostProcess(self):
        oParser = optparse.OptionParser()
        oParser.add_option('-j', '--json', action='store_true', default=False, help='Produce JSON output')
        oParser.add_option('-b', '--body', action='store_true', default=False, help='Print body')
        oParser.add_option('-H', '--header', action='store_true', default=False, help='Print header')
        (options, args) = oParser.parse_args(self.options.split(' '))

        sha256 = hashlib.sha256(self.data).hexdigest()
        if options.json:
            jsondata = {'sha256': sha256, 'subject': self.subject, 'date': self.date, 'to': self.to, 'from': self.from_, 'attachments': [{'index': key, 'longfilename': value.longfilename, 'mimetag': value.mimetag, 'size': len(value.data), 'sha256': hashlib.sha256(value.data).hexdigest(), 'magichex': binascii.b2a_hex(value.data[:4]).decode()} for key, value in self.dAttachments.items()]}
            print(json.dumps(jsondata))
        else:
            print('Sample email: sha256 %s' % sha256)
            print('Header stream index: %d' % self.headerStreamIndex)
            print('Subject: %s' % self.subject)
            print('Date: %s' % self.date)
            print('To: %s' % self.to)
            print('From: %s' % self.from_)
            print('Body stream index: %d' % self.bodyStreamIndex)
            for index in self.dAttachments.keys():
                print('Attachment %d (stream index %d): %s %s %d %s' % (index, self.dAttachments[index].streamIndex, self.dAttachments[index].longfilename, self.dAttachments[index].mimetag, len(self.dAttachments[index].data), hashlib.sha256(self.dAttachments[index].data).hexdigest()))
            if options.body:
                print('Body:')
                print(self.body)
            if options.header:
                print('Header:')
                print(self.header)

AddPlugin(cMSG)
