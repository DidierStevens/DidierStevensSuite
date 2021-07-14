#!/usr/bin/env python

from __future__ import print_function

__description__ = 'DNS server for serving files, exfiltration, tracking, wildcards, rcode testing and resolving'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2021/07/14'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2019/06/25: start
  2019/06/27: multiple strings per TXT record
  2019/07/16: option base64, refactoring
  2019/07/18: added payloads arguments, removed base64 option
  2019/07/19: refactoring, added exfiltrations
  2019/07/21: refactoring
  2019/07/24: added command track
  2019/08/05: bugfix
  2019/08/06: refactoring
  2019/08/13: updated man page
  2020/09/02: added DNS NULL support
  2020/11/09: cleanup DNS NULL support
  2021/01/15: added command rcode
  2021/01/16: added command wildcard
  2021/04/07: added command resolve
  2021/07/14: updated man page

Todo:
add option to control TCP size
"""

import argparse
import glob
import collections
import time
import sys
import textwrap
import os
import binascii
import string
import struct
import mmap
import copy
import os.path

try:
    import dnslib
    import dnslib.server
except ImportError:
    print('module dnslib is not installed, please install it (with pip, for example)')
    sys.exit()

def PrintManual():
    manual = '''
Manual:

This is a DNS server for serving files, exfiltration, tracking, wildcards, rcode testing and resolving.

When started, this Python program will start a DNS server (UDP only) listening on port 53 on all addresses of the host.
To serve DNS via TCP too, use option --tcp. You can select a different port with option -p, and a different address with option -a. With option -t, you can change the TTL of the replies. -u can be used to change the maximum length of the UDP packets.

You need to provide at least one command as argument. Commands are separated by space characters.

There are 5 different types of commands: serving files (type=payload), exfiltration (type=exfiltration), tracking (type=track), rcode testing (type=rcode), wildcards (type=wildcard) and resolving (type=resolve).

Here is an example to serve file test.exe BASE64 encoded via DNS TXT and DNS NULL records:

$> dnsresolver.py type=payload,label=executable,file=test.exe,encoding=base64

Commands consist of key-value pairs (key=value) separated by commas (,). If you need to use whitespace inside a command (for example for file names with space characters), you need to escape said whitespace with according to the rules of your shell.

Each command requires at least a key-value pair with key 'type'. This defines the type of command. Possible values are payload, exfiltration, track, wildcard, rcode and resolve.

A payload command takes the following key-value pairs:
  type=payload
  label=
  file=
  data=
  dataencoding=hex,base64,<EMPTYSTRING>
  encoding=hex,base64,dynamic,<EMPTYSTRING>

The label is a label in the domain name space that will be used to match DNS queries, like this: label.domain.tld. The label has to be the last leaf in the domain name space, and other labels (like domain and tld) are not checked by the dns resolver.
Key-value pair label is mandatory, except when a file is provided. When a file is provided and no label is provided, the label is derived from the filename (filename with path or extension).
The payload to be served via DNS TXT and DNS NULL records has to be provided via a file key-value pair (the value is the filename) or a data key-value pair. Data allows to serve a payload directly from the command line, without needing a file on disk.
The data is served as-is, unless a dataencoding key-value pair is provided. The data encoding can be hexadecimal (hex) or BASE64 (base64).
For example, the following command:

  type=payload,label=demo,data=414243,dataencoding=hex

will serve DNS TXT and DNS NULL records with content ABC (414243 hexadecimal). Only queries like demo.example.com, demo.word.didierstevens.com, ... (demo is the last leaf) will match and have a DNS TXT or DNS NULL reply. Non-matching queries result in an NXDOMAIN reply.

DNS resolver can serve files/data of arbitrary length. When the data can not be contained in a single UDP DNS TXT or NULL record (512 bytes), the program will offer to serve the reply via DNS (truncated flag), provided the --tcp flag was used.
DNS TXT and DNS NULL replies over TCP can be up to 64K in length.
If the data to be served exceeds the capacity of a single DNS TXT or DNS NULL reply (udp/tcp), the data will be split over several DNS TXT or DNS NULL records, using a counter as index.
The process works as follows (assume test.exe is at least 200.000 bytes long):

  type=payload,label=exe,file=test.exe

The first chunk of the file is served in replies to requests like exe.example.com or exe.0.example.com.
The second chunk of the file is served in replies to requests like exe.1.example.com.
The third chunk of the file is served in replies to requests like exe.2.example.com.
And so on.
The end-of-file is indicated with a NXDOMAIN reply. For example, if a file can be served via 2 chuncks (exe.0.example.com and exe.1.example.com), then a request for exe.2.example.com will result in a NXDOMAIN reply.

The content of a file (or data) is served as-is, unless a key-value pair encoding is used. Since some bytes can cause problems when parsed or transfered (like 0x00 bytes), encoding can be used to avoid these issues. DNS resolver supports hexadecimal (hex) and BASE64 (base64) encoding.
Encoding resolves issues with special characters, but increases the size of the data to be served via DNS TXT and DNS NULL records. For example, hexadecimal encoding doubles the size.
When value dynamic is provided as encoding, the DNS client can choose which encoding to use for encoding the reply.
Example:

  type=payload,label=exe,file=test.exe,encoding=dynamic

  a request for exe.0.example.com results in a DNS TXT or DNS NULL reply with the first chunck served as-is, e.g. without any encoding.
  a request for exe.0.hex.example.com results in a DNS TXT or DNS NULL reply with the first chunck served as hexadecimal encoded data.
  a request for exe.0.base64.example.com results in a DNS TXT or DNS NULL reply with the first chunck served as BASE64 encoded data.

FYI: tests can be done locally with nslookup, like this:

 nslookup -type=txt exe.0.hex.example.com 127.0.0.1

And with dig:

 dig.exe @127.0.0.1 exe.0.hex.example.com in null

An exfiltration command takes the following key-value pairs:
  type=exfiltration
  label=
  answer=

The label is mandatory: just like the payload command, it will be used to match queries.
Key-value pair answer is optional. It specifies the answer to be send as reply to each query. If no answer is provided, NXDOMAIN becomes the reply.
Example of answer usage:

  ./dnsresolver.py "type=exfiltration,label=dataleak,answer=. 60 IN A 127.0.0.1"

This defines the answer to be an Internet A record with IPv4 address 127.0.0.1.

Exfiltration can be used to exfiltrate data via DNS A queries using the following protocol:

The FQDN must contain the label defined in the exfiltration command. The data to be exfiltrated must be encoded in hexadecimal and placed to the left of the label, using one or more labels of maximum 63 characters each.

For example: 0000.00000010.00000000.04.41424344.dataleak.example.com
This FQDN follows the following protocol format:

  0000: 2 bytes, big endian, that represent the file number (0 in this example).
  00000010: 4 bytes, big endian, that represent the size of the file (16 in this example).
  00000000: 4 bytes, big endian, that represent the position of the data chunk to be written to the file (0 in this example).
  04: 1 byte, the length of the data chunk (4 in this example).
  41424344: the data chunk to be written to the file (4 bytes, ABCD in this example).

When all data chunks have been exfiltrated via A queries, a last A query is sent to "close" the file. This query just contains the file number and a file size of 0. Like this FQDN:
  0000.00000000.dataleak.example.com

The result of these 2 queries, is that a file with name dataleak-00000 is created in the working directory, 16 bytes long, filled with 0x00 bytes, except for the first 4 bytes: ABCD.

A track command takes the following key-value pairs:
  type=track
  label=
  logging=
  answer=

The label is mandatory: just like the payload command, it will be used to match queries.
Key-value pair logging is optional. If it is provided, DNS resolver will create a log with the value for key logging as keyword. For example, if the value is test, the logfile will be named test-TIMESTAMP.log, e.g. test-20190813-182220.log.
Key-value pair answer is optional. It specifies the answer to be send as reply to each query. If no answer is provided, NXDOMAIN becomes the reply.

The idea behind tracking, is to send FQDNs to targets to be tracked, for example in PDF documents that will be opened by the target. When opened, DNS resolution will take place and this allows tracking (e.g. knowing that the document has been received and opened).
Example of a track command:

  ./dnsresolver.py "type=track,label=pdf,answer=. 60 IN A 127.0.0.1"

Example of FQDNs:

  id01.pdf.example.com
  id02.pdf.example.com
  id03.pdf.example.com

When DNS resolver receives an A record query with the label as the last leaf (e.g. pdf.example.com), it will always reply with NXDOMAIN.
When DNS resolver receives an A record query where the label is not the last leaf (e.g. id01.pdf.example.com), it will reply with the provided answer, or NXDOMAIN if there is no provided answer.

An rcode command takes the following key-value pairs:
  type=rcode
  label=

The label is mandatory: just like the payload command, it will be used to match queries.

The idea behind rcode testing, is to be able to chose the rcode value in the DNS reply by chosing it via the DNS query.

For example, when setting up a command like:

  ./dnsresolver.py "type=rcode,label=rcodetesting"

A query like this:

  nslookup 4.rcodetesting.example.com

will result in a reply with an rcode equal to 4: not implemented.

Remark that intermediary DNS servers will probably change this rcode to 2: server failed.
This can be avoided by querying the DNS server directly:

  nslookup 4.rcodetesting.example.com 127.0.0.1

A wildcard command takes the following key-value pairs:
  type=wildcard
  label=
  logging=

The label is mandatory: just like the payload command, it will be used to match queries.
Key-value pair logging is optional. If it is provided, DNS resolver will create a log with the value for key logging as keyword. For example, if the value is test, the logfile will be named test-TIMESTAMP.log, e.g. test-20190813-182220.log.

With wildcard DNS, you can provide the reply to your query (A record) in the labels of the query.

For example, when setting up a command like:

  ./dnsresolver.py "type=wildcard,label=wc"

A query like this:

  nslookup 10.20.30.40.wc.example.com

will result in an A record reply with IPv4 address 10.20.30.40.

A resolve command takes the following key-value pairs:
  type=resolve
  label=
  answer=
  logging=

The label is mandatory: just like the payload command, it will be used to match queries.
Key-value pair logging is optional. If it is provided, DNS resolver will create a log with the value for key logging as keyword. For example, if the value is test, the logfile will be named test-TIMESTAMP.log, e.g. test-20190813-182220.log.

With resolve DNS, you can provide the reply to your query (A record) in the answer. There can be more than one answer, separated by semicolons (;).
The reply to a DNS request for a resolve label, is the configured answer. If there is more than one answer, a round-robin method is used.

For example, when setting up a command like:

  ./dnsresolver.py "type=resolve,label=roundrobin,answer=. 60 IN A 127.0.0.1;. 60 IN A 127.0.0.2"

A query like this:

  nslookup roundrobin.example.com

will result in an A record reply with IPv4 address 127.0.0.1.

A second, identical query (nslookup roundrobin.example.com) will result in an A record reply with IPv4 address 127.0.0.2.
A third, identical query (nslookup roundrobin.example.com) will result in an A record reply with IPv4 address 127.0.0.1.
And so on ...


Options --log and --log-prefix can be used to increase log details.

On Linux, listening on port 53 (a low port) requires root privileges:

  sudo python ./dnsresolver.py --log-prefix "type=track,label=pdf,logging=pdf,answer=. 60 IN A 127.0.0.1"

When using this tool for providing DNS services for a particular domain, DNS glue records must be defined (e.g. ns1.example.com) with the IPv4 address of the server that is running dnsresolver.py.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

TYPE_PAYLOAD = 'payload'
TYPE_EXFILTRATION = 'exfiltration'
TYPE_TRACK = 'track'
TYPE_RCODE = 'rcode'
TYPE_WILDCARD = 'wildcard'
TYPE_RESOLVE = 'resolve'
ENCODING_DYNAMIC = 'dynamic'
ENCODING_NONE = ''
ENCODING_BASE64 = 'base64'
ENCODING_HEX = 'hex'
PAYLOAD = 'payload'
DATA = 'data'
FILE = 'file'
TYPE = 'type'
LABEL = 'label'
ENCODING = 'encoding'
DATAENCODING = 'dataencoding'
FILES = 'files'
FILEHANDLE = 'filehandle'
FILEMMAP = 'filemmap'
ANSWER = 'answer'
LOGGING = 'logging'
INDEX = 'index'

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

def FormatTimeUTC(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.gmtime(epoch)[0:6]

def ParseCommand(command):
    dCommand = {}
    for element in command.split(','):
        name, value = element.split('=', 1)
        name = name.lower().strip()
        dCommand[name] = value
    if not TYPE in dCommand:
        raise Exception('Error command, type missing: ' + command)
    return dCommand

def DefineLabelFromFilename(filename):
    label = ''
    for char in os.path.basename(filename.lower().strip()):
        if char in string.ascii_lowercase or char in string.digits:
            label += char
        elif label != '':
            return label
    return label

def ValidatePayload(dCommand):
    for name, value in dCommand.items():
        if name != FILE and name != DATA:
            dCommand[name] = value.lower().strip()
    if not FILE in dCommand and not DATA in dCommand:
        raise Exception('Error payload: file/data missing')
    if FILE in dCommand and DATA in dCommand:
        raise Exception('Error payload: file & data present')
    if not LABEL in dCommand:
        if FILE in dCommand:
            dCommand[LABEL] = DefineLabelFromFilename(dCommand[FILE])
        else:
            raise Exception('Error payload: label & file missing')
    if not ENCODING in dCommand:
        dCommand[ENCODING] = ENCODING_NONE
    if not DATAENCODING in dCommand:
        dCommand[DATAENCODING] = ENCODING_NONE
    return dCommand

def ValidateExfiltration(dCommand):
    for name, value in dCommand.items():
        if name != ANSWER:
            dCommand[name] = value.lower().strip()
    if not LABEL in dCommand:
        raise Exception('Error exfiltration: label missing')
    if not ANSWER in dCommand:
        dCommand[ANSWER] = ''
    return dCommand

def ValidateTrack(dCommand):
    for name, value in dCommand.items():
        if name != ANSWER:
            dCommand[name] = value.lower().strip()
    if not LABEL in dCommand:
        raise Exception('Error track: label missing')
    if not ANSWER in dCommand:
        dCommand[ANSWER] = ''
    if LOGGING in dCommand:
        dCommand[LOGGING] = '%s-%s.log' % (dCommand[LOGGING], FormatTimeUTC())
    return dCommand

def ValidateRcode(dCommand):
    for name, value in dCommand.items():
        if name != ANSWER:
            dCommand[name] = value.lower().strip()
    if not LABEL in dCommand:
        raise Exception('Error rcode: label missing')
    return dCommand

def ValidateWildcard(dCommand):
    for name, value in dCommand.items():
        if name != ANSWER:
            dCommand[name] = value.lower().strip()
    if not LABEL in dCommand:
        raise Exception('Error wildcard: label missing')
    if not ANSWER in dCommand:
        dCommand[ANSWER] = ''
    if LOGGING in dCommand:
        dCommand[LOGGING] = '%s-%s.log' % (dCommand[LOGGING], FormatTimeUTC())
    return dCommand

def ValidateResolve(dCommand):
    for name, value in dCommand.items():
        if name != ANSWER:
            dCommand[name] = value.lower().strip()
    if not LABEL in dCommand:
        raise Exception('Error resolve: label missing')
    if not ANSWER in dCommand:
        dCommand[ANSWER] = ''
    dCommand[ANSWER] = dCommand[ANSWER].split(';')
    dCommand[INDEX] = 0
    return dCommand

def MatchLabel(dLabels, labelArg):
    for label in dLabels.keys():
        try:
            position = -1
            position = labelArg.index(label)
        except:
            pass
        if position != -1:
            return dLabels[label], label, position
    return None, None, None

def GetChunk(position, data):
    return [data[:position], data[position:]]

def Unpack(format, data):
    size = struct.calcsize(format)
    if len(data[:size]) != size:
        return []
    result = list(struct.unpack(format, data[:size]))
    result.append(data[size:])
    return result

def ParseInteger(argument):
    sign = 1
    if argument.startswith('+'):
        argument = argument[1:]
    elif argument.startswith('-'):
        argument = argument[1:]
        sign = -1
    if argument.startswith('0x'):
        return sign * int(argument[2:], 16)
    else:
        return sign * int(argument)

def ParseWildcardRequest(labels):
    if len(labels) != 4:
        return None
    for label in labels:
        try:
            number = int(label)
        except:
            return None
        if number < 0 or number > 255:
            return None
    return '. 60 IN A ' + '.'.join(labels)

class NULL():
    def __init__(self, strings):
        self.data = [bytes(string) for string in strings]

    def pack(self,buffer):
        for ditem in self.data:
            buffer.append(ditem)

class cMyResolver(dnslib.server.BaseResolver):
    def __init__(self, args):
        self.args = args
        self.ttl = dnslib.parse_time(self.args.ttl)
        self.payloads = {}
        self.exfiltrations = {}
        self.tracks = {}
        self.rcodes = {}
        self.wildcards = {}
        self.resolves = {}
        self.labels = {}
        for command in self.args.commands:
            dCommand = ParseCommand(command)
            if dCommand[TYPE] == TYPE_PAYLOAD:
                dPayload = ValidatePayload(dCommand)
                if FILE in dPayload:
                    content = File2String(dPayload[FILE])
                elif dPayload[DATAENCODING] == ENCODING_BASE64:
                    content = binascii.a2b_base64(dPayload[DATA])
                elif dPayload[DATAENCODING] == ENCODING_HEX:
                    content = binascii.a2b_hex(dPayload[DATA])
                else:
                    content = dPayload[DATA]
                self.payloads[dPayload[LABEL]] = {PAYLOAD: dPayload, DATA: {ENCODING_NONE: content}}
                self.labels[dPayload[LABEL]] = TYPE_PAYLOAD
            elif dCommand[TYPE] == TYPE_EXFILTRATION:
                dExfiltration = ValidateExfiltration(dCommand)
                dCommand[FILES] = {}
                self.exfiltrations[dCommand[LABEL]] = dExfiltration
                self.labels[dCommand[LABEL]] = TYPE_EXFILTRATION
            elif dCommand[TYPE] == TYPE_TRACK:
                dTrack = ValidateTrack(dCommand)
                self.tracks[dCommand[LABEL]] = dTrack
                self.labels[dCommand[LABEL]] = TYPE_TRACK
            elif dCommand[TYPE] == TYPE_RCODE:
                dRcode = ValidateRcode(dCommand)
                self.rcodes[dCommand[LABEL]] = dRcode
                self.labels[dCommand[LABEL]] = TYPE_RCODE
            elif dCommand[TYPE] == TYPE_WILDCARD:
                dWildcard = ValidateWildcard(dCommand)
                self.wildcards[dCommand[LABEL]] = dWildcard
                self.labels[dCommand[LABEL]] = TYPE_WILDCARD
            elif dCommand[TYPE] == TYPE_RESOLVE:
                dResolve = ValidateResolve(dCommand)
                self.resolves[dCommand[LABEL]] = dResolve
                self.labels[dCommand[LABEL]] = TYPE_RESOLVE
            else:
                raise Exception('Unknown type: %s' % dCommand[TYPE])
        self.maxSizeString = 250
        if self.args.tcp:
            self.maxCountStrings = 256
        else:
            self.maxCountStrings = 2

    def resolve(self, request, handler):
        reply = request.reply()
        if sys.version_info[0] > 2:
            labelsNormalized = [item.decode(errors='replace').lower().strip() for item in request.q.qname.label]
        else:
            labelsNormalized = [item.decode().lower().strip() for item in request.q.qname.label]
        type, label, position = MatchLabel(self.labels, labelsNormalized)
        replyNXDOMAIN = False
        rcode = None
        if type == None:
            replyNXDOMAIN = True
        elif type == TYPE_PAYLOAD:
            if request.q.qtype != dnslib.QTYPE.TXT and request.q.qtype != dnslib.QTYPE.NULL:
                replyNXDOMAIN = True
            elif not (len(labelsNormalized) >= 3 and labelsNormalized[0] in self.payloads.keys()):
                replyNXDOMAIN = True
            else:
                label = labelsNormalized[0]
                try:
                    index = 0
                    encodingIndex = 1
                    index = int(labelsNormalized[1])
                    encodingIndex = 2
                except:
                    pass
                encoding = self.payloads[label][PAYLOAD][ENCODING]
                if encoding == ENCODING_DYNAMIC:
                    if labelsNormalized[encodingIndex] in [ENCODING_BASE64, ENCODING_HEX]:
                        encoding = labelsNormalized[encodingIndex]
                    else:
                        encoding = ENCODING_NONE
                if not encoding in self.payloads[label][DATA]:
                    if encoding == ENCODING_BASE64:
                        self.payloads[label][DATA][ENCODING_BASE64] = binascii.b2a_base64(self.payloads[label][DATA][ENCODING_NONE]).strip()
                    elif encoding == ENCODING_HEX:
                        self.payloads[label][DATA][ENCODING_HEX] = binascii.b2a_hex(self.payloads[label][DATA][ENCODING_NONE]).strip()
                data = self.payloads[label][DATA][encoding]
                if index > len(data) / (self.maxSizeString * self.maxCountStrings):
                    replyNXDOMAIN = True
                else:
                    if handler.protocol == 'tcp' or not self.args.tcp:
                        dnsStrings = [data[(index * self.maxCountStrings + iter) * self.maxSizeString:(index * self.maxCountStrings + iter + 1) * self.maxSizeString] for iter in range(self.maxCountStrings)]
                        dnsStrings = [dnsString for dnsString in dnsStrings if len(dnsString) != 0]
                        if request.q.qtype == dnslib.QTYPE.TXT:
                            reply.add_answer(dnslib.RR(request.q.qname, dnslib.QTYPE.TXT, ttl=self.ttl, rdata=dnslib.TXT(dnsStrings)))
                        elif request.q.qtype == dnslib.QTYPE.NULL:
                            reply.add_answer(dnslib.RR(request.q.qname, dnslib.QTYPE.NULL, ttl=self.ttl, rdata=NULL(dnsStrings)))
                        else:
                            raise Exception('DNS payload: type unknown')
                    else:
                        reply.header.tc = True
        elif type == TYPE_EXFILTRATION:
            if request.q.qtype != dnslib.QTYPE.A:
                replyNXDOMAIN = True
            elif not (len(labelsNormalized) >= 4 and label in self.exfiltrations.keys()):
                replyNXDOMAIN = True
            else:
                hexdata = ''.join(labelsNormalized[0:position])
                try:
                    data = ''
                    data = binascii.a2b_hex(hexdata)
                except:
                    pass
                result = Unpack('>HI', data)
                if result != []:
                    filenumber, filesize, data = result
                    filename = '%s-%05d' % (label, filenumber)
                    if not filename in self.exfiltrations[label][FILES]:
                        try:
                            with open(filename, 'wb') as filehandle:
                                filehandle.write(b'\x00' * filesize)
                            filehandle = open(filename, 'r+b')
                            filemmap = mmap.mmap(filehandle.fileno(), filesize)
                            self.exfiltrations[label][FILES][filename] = {FILEHANDLE: filehandle, FILEMMAP: filemmap}
                        except:
                            pass
                    if filesize == 0:
                        if filename in self.exfiltrations[label][FILES]:
                            try:
                                self.exfiltrations[label][FILES][filename][FILEMMAP].close()
                                self.exfiltrations[label][FILES][filename][FILEMMAP] = None
                            except:
                                pass
                            try:
                                self.exfiltrations[label][FILES][filename][FILEHANDLE].close()
                                self.exfiltrations[label][FILES][filename][FILEHANDLE] = None
                            except:
                                pass
                    else:
                        result = Unpack('>IB', data)
                        if result != []:
                            fileposition, chuncksize, data = result
                            if chuncksize == len(data) and filename in self.exfiltrations[label][FILES]:
                                try:
                                    self.exfiltrations[label][FILES][filename][FILEMMAP][fileposition:fileposition + chuncksize] = data
                                except:
                                    pass
                if self.exfiltrations[label][ANSWER] == '':
                    replyNXDOMAIN = True
                else:
                    qname = request.q.qname
                    for rr in dnslib.RR.fromZone(self.exfiltrations[label][ANSWER]):
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
        elif type == TYPE_TRACK:
            if LOGGING in self.tracks[label]:
                with open(self.tracks[label][LOGGING], 'a') as f:
                    print('%s %s:%d %d %s' % (FormatTimeUTC(), handler.client_address[0], handler.client_address[1], position, '.'.join(labelsNormalized).encode('utf8').decode()), file=f)
            if request.q.qtype != dnslib.QTYPE.A: #a# handle AAAA too
                replyNXDOMAIN = True
            elif not label in self.tracks.keys():
                replyNXDOMAIN = True
            elif position == 0:
                replyNXDOMAIN = True
            else:
                if self.tracks[label][ANSWER] == '':
                    replyNXDOMAIN = True
                else:
                    qname = request.q.qname
                    for rr in dnslib.RR.fromZone(self.tracks[label][ANSWER]):
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
        elif type == TYPE_RCODE:
            if position != 1:
                replyNXDOMAIN = True
            elif not label in self.rcodes.keys():
                replyNXDOMAIN = True
            else:
                try:
                    rcode = abs(ParseInteger(labelsNormalized[0])) % 0x100
                except:
                    replyNXDOMAIN = True
        elif type == TYPE_WILDCARD:
            if LOGGING in self.wildcards[label]:
                with open(self.wildcards[label][LOGGING], 'a') as f:
                    print('%s %s:%d %d %s' % (FormatTimeUTC(), handler.client_address[0], handler.client_address[1], position, '.'.join(labelsNormalized).encode('utf8').decode()), file=f)
            if request.q.qtype != dnslib.QTYPE.A: #a# handle AAAA too
                replyNXDOMAIN = True
            elif not label in self.wildcards.keys():
                replyNXDOMAIN = True
            elif position == 0:
                replyNXDOMAIN = True
            else:
                qname = request.q.qname
                zoneWildcard = ParseWildcardRequest(labelsNormalized[:position])
                if zoneWildcard == None:
                    replyNXDOMAIN = True
                else:
                    for rr in dnslib.RR.fromZone(zoneWildcard):
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
        elif type == TYPE_RESOLVE:
            if position != 0:
                replyNXDOMAIN = True
            else:
                if LOGGING in self.resolves[label]:
                    with open(self.resolves[label][LOGGING], 'a') as f:
                        print('%s %s:%d %d %s' % (FormatTimeUTC(), handler.client_address[0], handler.client_address[1], position, '.'.join(labelsNormalized).encode('utf8').decode()), file=f)
                if request.q.qtype == dnslib.QTYPE.A:
                    qname = request.q.qname
                    answer = self.resolves[label][ANSWER][self.resolves[label][INDEX]]
                    self.resolves[label][INDEX] = (self.resolves[label][INDEX] + 1) % len(self.resolves[label][ANSWER])
                    for rr in dnslib.RR.fromZone(answer):
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
                else:
                    replyNXDOMAIN = True
        else:
            replyNXDOMAIN = True
        if replyNXDOMAIN:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
        if rcode != None:
            reply.header.rcode = rcode
        return reply

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oArgumentParser = argparse.ArgumentParser(description=__description__ + moredesc)
    oArgumentParser.add_argument('-m', '--man', action='store_true', default=False, help='Print manual')
    oArgumentParser.add_argument('--version', action='version', version=__version__)
    oArgumentParser.add_argument('-t', '--ttl', default='60s', metavar='<ttl>', help='Response TTL (default: 60s)')
    oArgumentParser.add_argument('-p', '--port', type=int, default=53, metavar='<port>', help='Server port (default:53)')
    oArgumentParser.add_argument('-a', '--address', default='', metavar='<address>', help='Listen address (default:all)')
    oArgumentParser.add_argument('-u', '--udplen', type=int, default=0, metavar='<udplen>', help='Max UDP packet length (default:0)')
    oArgumentParser.add_argument('--tcp', action='store_true', default=False, help='TCP server (default: UDP only)')
    oArgumentParser.add_argument('--log', default='request,reply,truncated,error', help='Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)')
    oArgumentParser.add_argument('--log-prefix', action='store_true',default=False, help='Log prefix (timestamp/handler/resolver) (default: False)')
    oArgumentParser.add_argument('commands', nargs='*', help='commands to serve')
    args = oArgumentParser.parse_args()

    if args.man:
        oArgumentParser.print_help()
        PrintManual()
        return

    if len(args.commands) == 0:
        print('Please provide a command!')
        return

    oMyResolver = cMyResolver(args)
    oDNSLogger = dnslib.server.DNSLogger(args.log, args.log_prefix)

    print('Starting Resolver (%s:%d) [%s]' % (args.address or '*', args.port, 'UDP/TCP' if args.tcp else 'UDP'))

    if args.udplen:
        dnslib.server.DNSHandler.udplen = args.udplen

    oUDPDNSServer = dnslib.server.DNSServer(oMyResolver, port=args.port, address=args.address, logger=oDNSLogger)
    oUDPDNSServer.start_thread()

    if args.tcp:
        oTCPDNSServer = dnslib.server.DNSServer(oMyResolver, port=args.port, address=args.address, tcp=True, logger=oDNSLogger)
        oTCPDNSServer.start_thread()

    while oUDPDNSServer.isAlive():
        time.sleep(1)

def Mainxx():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

if __name__ == '__main__':
    Main()
