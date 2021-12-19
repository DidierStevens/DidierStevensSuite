#!/usr/bin/env python

from __future__ import print_function

__description__ = 'Analyze Cobalt Strike HTTP/DNS beacon traffic'
__author__ = 'Didier Stevens'
__version__ = '0.0.4'
__date__ = '2021/12/12'

"""

Source code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2021/04/17: start
  2021/04/18: continue
  2021/04/19: added option -r
  2021/04/20: added option -Y; continue
  2021/04/22: continue
  2021/04/23: continue
  2021/04/24: continue
  2021/10/07: updated missing modules logic
  2021/10/17: 0.0.2 added option -i; -r unknown and -k unknown
  2021/10/28: handle fake gzip
  2021/10/30: continue instructions processing
  2021/10/31: added request methods
  2021/11/01: refactoring instructions processing
  2021/11/05: refactoring instructions processing
  2021/11/17: 0.0.3 refactoring crypto & parser
  2021/11/20: added constants from https://github.com/verctor/Cobalt_Homework/blob/master/scripts/define.py
  2021/11/26: merging HTTP and DNS
  2021/12/12: 0.0.4 bugfix HMAC invalid; extra constants https://github.com/DidierStevens/Beta/issues/5

Todo:
  add support for non-default DNS labels
"""

import optparse
import glob
import collections
import time
import sys
import textwrap
import os
import binascii
import struct
import hashlib
import hmac
import base64
try:
    import pyshark
except ImportError:
    print('pyshark module required: pip install pyshark')
    exit(-1)
try:
    import Crypto.Cipher.AES
except ImportError:
    print('Crypto.Cipher.AES module required: pip install pycryptodome')
    exit(-1)

def PrintManual():
    manual = '''
Manual:

This tool can decode (and decrypt if encrypted) Cobalt Strike network traffic.
For HTTP and DNS beacons. HTTPS works too provided the TLS traffic is decrypted.


# https://github.com/nccgroup/pybeacon

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

class cOutput():
    def __init__(self, filenameOption=None):
        self.starttime = time.time()
        self.filenameOption = filenameOption
        self.separateFiles = False
        self.progress = False
        self.console = False
        self.fOut = None
        self.rootFilenames = {}
        if self.filenameOption:
            if self.ParseHash(self.filenameOption):
                if not self.separateFiles and self.filename != '':
                    self.fOut = open(self.filename, 'w')
            elif self.filenameOption != '':
                self.fOut = open(self.filenameOption, 'w')
        self.dReplacements = {}

    def Replace(self, line):
        for key, value in self.dReplacements.items():
            line = line.replace(key, value)
        return line

    def ParseHash(self, option):
        if option.startswith('#'):
            position = self.filenameOption.find('#', 1)
            if position > 1:
                switches = self.filenameOption[1:position]
                self.filename = self.filenameOption[position + 1:]
                for switch in switches:
                    if switch == 's':
                        self.separateFiles = True
                    elif switch == 'p':
                        self.progress = True
                    elif switch == 'c':
                        self.console = True
                    elif switch == 'l':
                        pass
                    elif switch == 'g':
                        if self.filename != '':
                            extra = self.filename + '-'
                        else:
                            extra = ''
                        self.filename = '%s-%s%s.txt' % (os.path.splitext(os.path.basename(sys.argv[0]))[0], extra, self.FormatTime())
                    else:
                        return False
                return True
        return False

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

    def RootUnique(self, root):
        if not root in self.rootFilenames:
            self.rootFilenames[root] = None
            return root
        iter = 1
        while True:
            newroot = '%s_%04d' % (root, iter)
            if not newroot in self.rootFilenames:
                self.rootFilenames[newroot] = None
                return newroot
            iter += 1

    def Line(self, line, eol='\n'):
        line = self.Replace(line)
        if self.fOut == None or self.console:
            try:
                print(line, end=eol)
            except UnicodeEncodeError:
                encoding = sys.stdout.encoding
                print(line.encode(encoding, errors='backslashreplace').decode(encoding), end=eol)
#            sys.stdout.flush()
        if self.fOut != None:
            self.fOut.write(line + '\n')
            self.fOut.flush()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (self.FormatTime(), line))

    def Filename(self, filename, index, total):
        self.separateFilename = filename
        if self.progress:
            if index == 0:
                eta = ''
            else:
                seconds = int(float((time.time() - self.starttime) / float(index)) * float(total - index))
                eta = 'estimation %d seconds left, finished %s ' % (seconds, self.FormatTime(time.time() + seconds))
            PrintError('%d/%d %s%s' % (index + 1, total, eta, self.separateFilename))
        if self.separateFiles and self.filename != '':
            oFilenameVariables = cVariables()
            oFilenameVariables.SetVariable('f', self.separateFilename)
            basename = os.path.basename(self.separateFilename)
            oFilenameVariables.SetVariable('b', basename)
            oFilenameVariables.SetVariable('d', os.path.dirname(self.separateFilename))
            root, extension = os.path.splitext(basename)
            oFilenameVariables.SetVariable('r', root)
            oFilenameVariables.SetVariable('ru', self.RootUnique(root))
            oFilenameVariables.SetVariable('e', extension)

            self.Close()
            self.fOut = open(oFilenameVariables.Instantiate(self.filename), 'w')

    def Close(self):
        if self.fOut != None:
            self.fOut.close()
            self.fOut = None

def InstantiateCOutput(options):
    filenameOption = None
    if options.output != '':
        filenameOption = options.output
    return cOutput(filenameOption)

class cCrypto(object):
    CS_FIXED_IV = b'abcdefghijklmnop'

    def __init__(self, rawkey='', hmacaeskeys=''):
        self.rawkey = rawkey
        self.hmacaeskeys = hmacaeskeys
        if self.rawkey != '' and self.rawkey != 'unknown':
            sha256digest = hashlib.sha256(binascii.a2b_hex(self.rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif self.hmacaeskeys != '' and self.hmacaeskeys != 'unknown':
            self.hmackey = binascii.a2b_hex(self.hmacaeskeys.split(':')[0])
            self.aeskey = binascii.a2b_hex(self.hmacaeskeys.split(':')[1])
        else:
            self.hmackey = None
            self.aeskey = None

    def Decrypt(self, data):
        if self.aeskey == None:
            return data
        encryptedData = data[:-16]
        hmacSignatureMessage = data[-16:]
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        if hmacSignatureMessage != hmacsSgnatureCalculated:
            raise Exception('HMAC signature invalid')
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, __class__.CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        return decryptedData

    def Encrypt(self, data):
        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, __class__.CS_FIXED_IV)
        encryptedData = cypher.encrypt(data)
        hmacsSgnatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        return encryptedData + hmacsSgnatureCalculated

class cStruct(object):
    def __init__(self, data):
        self.data = data
        self.originaldata = data

    def Unpack(self, format):
        formatsize = struct.calcsize(format)
        if len(self.data) < formatsize:
            raise Exception('Not enough data')
        tounpack = self.data[:formatsize]
        self.data = self.data[formatsize:]
        result = struct.unpack(format, tounpack)
        if len(result) == 1:
            return result[0]
        else:
            return result

    def Truncate(self, length):
        self.data = self.data[:length]

    def GetBytes(self, length=None):
        if length == None:
            length = len(self.data)
        result = self.data[:length]
        self.data = self.data[length:]
        return result

    def GetString(self, format):
        stringLength = self.Unpack(format)
        return self.GetBytes(stringLength)

    def Length(self):
        return len(self.data)

class cCSInstructions(object):
    CS_INSTRUCTION_TYPE_INPUT = 'Input'
    CS_INSTRUCTION_TYPE_OUTPUT = 'Output'
    CS_INSTRUCTION_TYPE_METADATA = 'Metadata'
    CS_INSTRUCTION_TYPE_SESSIONID = 'SessionId'

    CS_INSTRUCTION_NONE = 0
    CS_INSTRUCTION_APPEND = 1
    CS_INSTRUCTION_PREPEND = 2
    CS_INSTRUCTION_BASE64 = 3
    CS_INSTRUCTION_PRINT = 4
    CS_INSTRUCTION_PARAMETER = 5
    CS_INSTRUCTION_HEADER = 6
    CS_INSTRUCTION_BUILD = 7
    CS_INSTRUCTION_NETBIOS = 8
    CS_INSTRUCTION_CONST_PARAMETER = 9
    CS_INSTRUCTION_CONST_HEADER = 10
    CS_INSTRUCTION_NETBIOSU = 11
    CS_INSTRUCTION_URI_APPEND = 12
    CS_INSTRUCTION_BASE64URL = 13
    CS_INSTRUCTION_STRREP = 14
    CS_INSTRUCTION_MASK = 15
    CS_INSTRUCTION_CONST_HOST_HEADER = 16

    def __init__(self, instructionType, instructions):
        self.instructionType = instructionType
        self.instructions = instructions

    @staticmethod
    def StartsWithGetRemainder(strIn, strStart):
        if strIn.startswith(strStart):
            return True, strIn[len(strStart):]
        else:
            return False, None

    @staticmethod
    def BASE64URLDecode(data):
        paddingLength = 4 - len(data) % 4
        if paddingLength <= 2:
            data += b'=' * paddingLength
        return base64.b64decode(data, b'-_')

    @staticmethod
    def NETBIOSDecode(netbios):
        dTranslate = {
            ord(b'A'): ord(b'0'),
            ord(b'B'): ord(b'1'),
            ord(b'C'): ord(b'2'),
            ord(b'D'): ord(b'3'),
            ord(b'E'): ord(b'4'),
            ord(b'F'): ord(b'5'),
            ord(b'G'): ord(b'6'),
            ord(b'H'): ord(b'7'),
            ord(b'I'): ord(b'8'),
            ord(b'J'): ord(b'9'),
            ord(b'K'): ord(b'A'),
            ord(b'L'): ord(b'B'),
            ord(b'M'): ord(b'C'),
            ord(b'N'): ord(b'D'),
            ord(b'O'): ord(b'E'),
            ord(b'P'): ord(b'F'),
        }
        return binascii.a2b_hex(bytes([dTranslate[char] for char in netbios]))

    def GetInstructions(self):
        for result in self.instructions.split(';'):
            match, remainder = __class__.StartsWithGetRemainder(result, '7:%s,' % self.instructionType)
            if match:
                if self.instructionType in [__class__.CS_INSTRUCTION_TYPE_OUTPUT, __class__.CS_INSTRUCTION_TYPE_METADATA]:
                    return ','.join(remainder.split(',')[::-1])
                else:
                    return remainder
        return ''

    def ProcessInstructions(self, rawdata):
        instructions = self.GetInstructions()
        if instructions == '':
            instructions = []
        else:
            instructions = [instruction for instruction in instructions.split(',')]
        data = rawdata
        for instruction in instructions:
            instruction = instruction.split(':')
            opcode = int(instruction[0])
            operands = instruction[1:]
            if opcode == __class__.CS_INSTRUCTION_NONE:
                pass
            elif opcode == __class__.CS_INSTRUCTION_APPEND:
                if self.instructionType == __class__.CS_INSTRUCTION_TYPE_METADATA:
                    data = data[:-len(operands[0])]
                else:
                    data = data[:-int(operands[0])]
            elif opcode == __class__.CS_INSTRUCTION_PREPEND:
                if self.instructionType == __class__.CS_INSTRUCTION_TYPE_METADATA:
                    data = data[len(operands[0]):]
                else:
                    data = data[int(operands[0]):]
            elif opcode == __class__.CS_INSTRUCTION_BASE64:
                data = binascii.a2b_base64(data)
            elif opcode == __class__.CS_INSTRUCTION_PRINT:
                pass
            elif opcode == __class__.CS_INSTRUCTION_PARAMETER:
                pass
            elif opcode == __class__.CS_INSTRUCTION_HEADER:
                pass
            elif opcode == __class__.CS_INSTRUCTION_BUILD:
                pass
            elif opcode == __class__.CS_INSTRUCTION_NETBIOS:
                data = __class__.NETBIOSDecode(data.upper())
            elif opcode == __class__.CS_INSTRUCTION_CONST_PARAMETER:
                pass
            elif opcode == __class__.CS_INSTRUCTION_CONST_HEADER:
                pass
            elif opcode == __class__.CS_INSTRUCTION_NETBIOSU:
                data = __class__.NETBIOSDecode(data)
            elif opcode == __class__.CS_INSTRUCTION_URI_APPEND:
                pass
            elif opcode == __class__.CS_INSTRUCTION_BASE64URL:
                data = __class__.BASE64URLDecode(data)
            elif opcode == __class__.CS_INSTRUCTION_STRREP:
                data = data.replace(operands[0], operands[1])
            elif opcode == __class__.CS_INSTRUCTION_MASK:
                xorkey = data[0:4]
                ciphertext = data[4:]
                data = []
                for iter, value in enumerate(ciphertext):
                    data.append(value ^ xorkey[iter % 4])
                data = bytes(data)
            elif opcode == __class__.CS_INSTRUCTION_CONST_HOST_HEADER:
                pass
            else:
                raise Exception('Unknown instruction opcode: %d' % opcode)
        return data

class cCSParser(object):
    BEACON_COMMAND_SLEEP = 4
    BEACON_COMMAND_DATA_JITTER = 6
    BEACON_COMMAND_RUN = 78

    BEACON_COMMANDS = {
        BEACON_COMMAND_SLEEP:  'SLEEP',
        BEACON_COMMAND_DATA_JITTER:  'DATA_JITTER',
        11: 'DOWNLOAD_START',
        32: 'LIST_PROCESSES',

        3: 'EXIT',
        5: 'CD',
        8: 'CHECKIN',
        11: 'DOWNLOAD',
        12: 'EXECUTE',
        13: 'Tasked beacon to spawn features to default process',
        27: 'GETUID',
        28: 'REVERT_TOKEN',
        33: 'KILL',
        39: 'PWD',
        41: 'JOBS',
        48: 'IP_CONFIG',
        53: 'LIST_FILES',
        54: 'MKDIR',
        55: 'DRIVES',
        56: 'RM',
        72: 'SETENV',
        73: 'CP',
        74: 'MV',
        77: 'GETPRIVS',
        BEACON_COMMAND_RUN: 'RUN',
        80: 'DLLLOAD',
        85: 'ARGUE',
        95: 'GETSYSTEM',
    }

    BEACON_OUTPUT = {
        1: 'OUTPUT_KEYSTROKES',
        2: 'DOWNLOAD_START',
        3: 'OUTPUT_SCREENSHOT',
        4: 'SOCKS_DIE',
        5: 'SOCKS_WRITE',
        6: 'SOCKS_RESUME',
        7: 'SOCKS_PORTFWD',
        8: 'DOWNLOAD_WRITE',
        9: 'DOWNLOAD_COMPLETE',
        10: 'BEACON_LINK',
        11: 'DEAD_PIPE',
        12: 'BEACON_CHECKIN', # maybe?
        13: 'BEACON_ERROR',
        14: 'PIPES_REGISTER', # unsure?
        15: 'BEACON_IMPERSONATED',
        16: 'BEACON_GETUID',
        17: 'BEACON_OUTPUT_PS',
        18: 'ERROR_CLOCK_SKEW',
        19: 'BEACON_GETCWD',
        20: 'BEACON_OUTPUT_JOBS',
        21: 'BEACON_OUTPUT_HASHES',
        22: 'TODO', # find out
        23: 'SOCKS_ACCEPT',
        24: 'BEACON_OUTPUT_NET',
        25: 'BEACON_OUTPUT_PORTSCAN',
        26: 'BEACON_EXIT',
    }

    verctor_command = {
        'COMMAND_SPAWN' : 1,
        'COMMAND_SHELL' : 2,
        'COMMAND_DIE' : 3,
        'COMMAND_SLEEP' : 4,
        'COMMAND_CD' : 5,
#        'COMMAND_KEYLOG_START' : 6,
        'COMMAND_KEYLOG_STOP' : 7,
        'COMMAND_CHECKIN': 8,
        'COMMAND_INJECT_PID' : 9,
        'COMMAND_UPLOAD' : 10,
        'COMMAND_DOWNLOAD': 11,
        'COMMAND_EXECUTE': 12,
        'COMMAND_SPAWN_PROC_X86' : 13,
        'COMMAND_PROXYLISTENER_CONNECTMESSAGE' : 14,
        'COMMAND_PROXYLISTENER_WRITEMESSAGE' : 15,
        'COMMAND_PROXYLISTENER_CLOSEMESSAGE' : 16,
        'COMMAND_PROXYLISTENER_LISTENMESSAGE' : 17,
        'COMMAND_INJECT_PING' : 18,
        'COMMAND_DOWNLOAD_CANCEL': 19,
        'COMMAND_FORWARD_PIPE_DATA': 22,
        'COMMAND_UNLINK': 23,
        'COMMAND_PIPE_PONG': 24,
        'COMMAND_GET_SYSTEM': 25,
        'COMMAND_GETUID': 27,
        'COMMAND_REV2SELF': 28,
        'COMMAND_TIMESTOMP': 29,
        'COMMAND_STEALTOKEN': 31,
        'COMMAND_PS': 32,
        'COMMAND_KILL': 33,
        'COMMAND_KerberosTicketUse': 34,
        'COMMAND_Kerberos_Ticket_Purge': 35,
        'COMMAND_POWERSHELL_IMPORT': 37,
        'COMMAND_RUNAS': 38,
        'COMMAND_PWD': 39,
        'COMMAND_JOB_REGISTER' : 40,
        'COMMAND_JOBS': 41,
        'COMMAND_JOB_KILL': 42,
        'COMMAND_INJECTX64_PID' : 43,
        'COMMAND_SPAWNX64' : 44,
        'COMMAND_VNC_INJECT': 45,
        'COMMAND_VNC_INJECT_X64': 46,
        'COMMAND_PAUSE': 47,
        'COMMAND_IPCONFIG': 48,
        'COMMAND_MAKE_TOKEN': 49,
        'COMMAND_PORT_FORWARD': 50,
        'COMMAND_PORT_FORWARD_STOP': 51,
        'COMMAND_BIND_STAGE': 52,
        'COMMAND_LS': 53,
        'COMMAND_MKDIR': 54,
        'COMMAND_DRIVERS': 55,
        'COMMAND_RM': 56,
        'COMMAND_STAGE_REMOTE_SMB': 57,
        'COMMAND_START_SERVICE': 58,  # not sure
        'COMMAND_HTTPHOSTSTRING': 59,
        'COMMAND_OPEN_PIPE': 60,
        'COMMAND_CLOSE_PIPE': 61,
        'COMMAND_JOB_REGISTER_IMPERSONATE' : 62,
        'COMMAND_SPAWN_POWERSHELLX86' : 63,
        'COMMAND_SPAWN_POWERSHELLX64' : 64,
        'COMMAND_INJECT_POWERSHELLX86_PID' : 65,
        'COMMAND_INJECT_POWERSHELLX64_PID' : 66,
        'COMMAND_UPLOAD_CONTINUE' : 67,
        'COMMAND_PIPE_OPEN_EXPLICIT' : 68,
        'COMMAND_SPAWN_PROC_X64' : 69,
        'COMMAND_JOB_SPAWN_X86' : 70,
        'COMMAND_JOB_SPAWN_X64' : 71,
        'COMMAND_SETENV' : 72,
        'COMMAND_FILE_COPY' : 73,
        'COMMAND_FILE_MOVE' : 74,
        'COMMAND_PPID' : 75,
        'COMMAND_RUN_UNDER_PID' : 76,
        'COMMAND_GETPRIVS' : 77,
        'COMMAND_EXECUTE_JOB' : 78,
        'COMMAND_PSH_HOST_TCP' : 79,
        'COMMAND_DLL_LOAD' : 80,
        'COMMAND_REG_QUERY' : 81,
        'COMMAND_LSOCKET_TCPPIVOT' : 82,
        'COMMAND_ARGUE_ADD' : 83,
        'COMMAND_ARGUE_REMOVE' : 84,
        'COMMAND_ARGUE_LIST' : 85,
        'COMMAND_TCP_CONNECT' : 86,
        'COMMAND_JOB_SPAWN_TOKEN_X86' : 87,
        'COMMAND_JOB_SPAWN_TOKEN_X64' : 88,
        'COMMAND_SPAWN_TOKEN_X86' : 89,
        'COMMAND_SPAWN_TOKEN_X64' : 90,
        'COMMAND_INJECTX64_PING' : 91,
        'COMMAND_BLOCKDLLS' : 92,
        'COMMAND_SPAWNAS_X86' : 93,
        'COMMAND_SPAWNAS_X64' : 94,
        'COMMAND_INLINE_EXECUTE' : 95,
        'COMMAND_RUN_INJECT_X86' : 96,
        'COMMAND_RUN_INJECT_X64' : 97,
        'COMMAND_SPAWNU_X86' : 98,
        'COMMAND_SPAWNU_X64' : 99,
        'COMMAND_INLINE_EXECUTE_OBJECT' : 100,
        'COMMAND_JOB_REGISTER_MSGMODE' : 101,
        'COMMAND_LSOCKET_BIND_LOCALHOST' : 102,
    }

    verctor_result = {
        'CALLBACK_OUTPUT' : 0,
        'CALLBACK_KEYSTROKES' : 1,
        'CALLBACK_FILE' : 2,
        'CALLBACK_SCREENSHOT' : 3,
        'CALLBACK_CLOSE' : 4,
        'CALLBACK_READ' : 5,
        'CALLBACK_CONNECT' : 6,
        'CALLBACK_PING' : 7,
        'CALLBACK_FILE_WRITE' : 8,
        'CALLBACK_FILE_CLOSE' : 9,
        'CALLBACK_PIPE_OPEN' : 10,
        'CALLBACK_PIPE_CLOSE' : 11,
        'CALLBACK_PIPE_READ' : 12,
        'CALLBACK_POST_ERROR' : 13,
        'CALLBACK_PIPE_PING' : 14,
        'CALLBACK_TOKEN_STOLEN' : 15,
        'CALLBACK_TOKEN_GETUID' : 16,
        'CALLBACK_PROCESS_LIST' : 17,
        'CALLBACK_POST_REPLAY_ERROR' : 18,
        'CALLBACK_PWD' : 19,
        'CALLBACK_JOBS' : 20,
        'CALLBACK_HASHDUMP' : 21,
        'CALLBACK_PENDING' : 22,
        'CALLBACK_ACCEPT' : 23,
        'CALLBACK_NETVIEW' : 24,
        'CALLBACK_PORTSCAN' : 25,
        'CALLBACK_DEAD' : 26,
        'CALLBACK_SSH_STATUS' : 27,
        'CALLBACK_CHUNK_ALLOCATE' : 28,
        'CALLBACK_CHUNK_SEND' : 29,
        'CALLBACK_OUTPUT_OEM' : 30,
        'CALLBACK_ERROR' : 31,
        'CALLBACK_OUTPUT_UTF8' : 32
    }

    def __init__(self, rawkey, hmacaeskeys, hexadecimal, postdataIsMultipartFormat, transform, extract, oOutput):
        self.rawkey = rawkey
        self.hmacaeskeys = hmacaeskeys
        self.hexadecimal = hexadecimal
        self.postdataIsMultipartFormat = postdataIsMultipartFormat
        self.transform = transform
        self.extract = extract
        self.oOutput = oOutput
        self.dCommandsSummary = {}
        self.dCallbacksSummary = {}

        if rawkey == '':
            self.oCrypto = cCrypto(hmacaeskeys=hmacaeskeys)
        else:
            self.oCrypto = cCrypto(rawkey=rawkey)

        for key, value in __class__.verctor_command.items():
            __class__.BEACON_COMMANDS[value] = key
        for key, value in __class__.verctor_result.items():
            __class__.BEACON_OUTPUT[value] = key

    @staticmethod
    def FormatTime(epoch=None):
        if epoch == None:
            epoch = time.time()
        return '%04d%02d%02d-%02d%02d%02d' % time.gmtime(epoch)[0:6]

    def LookupCommand(self, commandID):
        return self.BEACON_COMMANDS.get(commandID, 'UNKNOWN')

    def LookupCallback(self, callbackID):
        return self.BEACON_OUTPUT.get(callbackID, 'UNKNOWN')

    def ExtractPayload(self, data):
        if self.extract:
            with open('payload-%s.vir' % hashlib.md5(data).hexdigest(), 'wb') as fWrite:
                fWrite.write(data)

    def ProcessPostPacketDataSub(self, data):
        try:
            oStructData = cStruct(self.oCrypto.Decrypt(data))
        except Exception as e:
            if e.args != ('HMAC signature invalid',):
                raise
            self.oOutput.Line('HMAC signature invalid')
            self.oOutput.Line('')
            return
        counter = oStructData.Unpack('>I')
        self.oOutput.Line('Counter: %d' % counter)
        oStructCallbackdata = cStruct(oStructData.GetString('>I'))
        callback = oStructCallbackdata.Unpack('>I')
        callbackdata = oStructCallbackdata.GetBytes()
        oStructCallbackdataToParse = cStruct(callbackdata)
        self.oOutput.Line('Callback: %d %s' % (callback, self.LookupCallback(callback)))
        self.dCallbacksSummary[callback] = self.dCallbacksSummary.get(callback, 0) + 1
        if callback in [0, 25]:
            self.oOutput.Line('-' * 100)
            self.oOutput.Line(callbackdata.decode())
            self.oOutput.Line('-' * 100)
        elif callback == 22:
            self.oOutput.Line(repr(callbackdata[:4]))
            self.oOutput.Line('-' * 100)
            self.oOutput.Line(callbackdata[4:].decode('latin'))
            self.oOutput.Line('-' * 100)
        elif callback == 2:
            parameter1, length = oStructCallbackdataToParse.Unpack('>II')
            filenameDownload = oStructCallbackdataToParse.GetBytes()
            self.oOutput.Line(' parameter1: %d' % parameter1)
            self.oOutput.Line(' length: %d' % length)
            self.oOutput.Line(' filenameDownload: %s' % filenameDownload.decode())
        elif callback in [17, 30, 32]:
            self.oOutput.Line(callbackdata.decode())
        elif callback in [3, 8]:
            self.oOutput.Line(' Length: %d' % len(callbackdata[4:]))
            self.oOutput.Line(' MD5: ' + hashlib.md5(callbackdata[4:]).hexdigest())
            self.ExtractPayload(callbackdata[4:])
        else:
            self.oOutput.Line(repr(callbackdata))
        extradata = oStructData.GetBytes()[:-16] # drop hmac
        if len(extradata) > 0:
            self.oOutput.Line('Extra packet data: %s' % repr(extradata))

        self.oOutput.Line('')

    def ProcessPostPacketData(self, hexdata):
        if self.hexadecimal:
            rawdata = binascii.a2b_hex(hexdata)
        else:
            rawdata = hexdata
        self.oOutput.Line('Length raw data: %s' % len(rawdata))
        rawdata = cCSInstructions(cCSInstructions.CS_INSTRUCTION_TYPE_OUTPUT, self.transform).ProcessInstructions(rawdata)
        if rawdata == b'':
            self.oOutput.Line('No data')
            self.oOutput.Line('')
            return
        if self.rawkey == 'unknown' or self.hmacaeskeys == 'unknown':
            self.oOutput.Line(binascii.b2a_hex(rawdata).decode())
            self.oOutput.Line('')
            return
        if self.postdataIsMultipartFormat:
            oStructData = cStruct(rawdata)
            while oStructData.Length() > 0:
                self.ProcessPostPacketDataSub(oStructData.GetString('>I'))
        else:
            self.ProcessPostPacketDataSub(rawdata)

    def ProcessReplyPacketData(self, hexdata):
        if self.hexadecimal:
            rawdata = binascii.a2b_hex(hexdata)
        else:
            rawdata = hexdata
        self.oOutput.Line('Length raw data: %s' % len(rawdata))
        rawdata = cCSInstructions(cCSInstructions.CS_INSTRUCTION_TYPE_INPUT, self.transform).ProcessInstructions(rawdata)
        if rawdata == b'':
            self.oOutput.Line('No data')
            self.oOutput.Line('')
            return
        if self.rawkey == 'unknown' or self.hmacaeskeys == 'unknown':
            self.oOutput.Line(binascii.b2a_hex(rawdata).decode())
            self.oOutput.Line('')
            return
        try:
            data = self.oCrypto.Decrypt(rawdata)
        except Exception as e:
            if e.args != ('HMAC signature invalid',):
                raise
            self.oOutput.Line('HMAC signature invalid')
            self.oOutput.Line('')
            return
        if data == b'':
            self.oOutput.Line('No data')
        elif data.startswith(b'MZ'):
            self.oOutput.Line('MZ payload detected')
            self.oOutput.Line(' MD5: ' + hashlib.md5(data).hexdigest())
            self.ExtractPayload(data)
        else:
            oStructData = cStruct(data)
            timestamp, datasize = oStructData.Unpack('>II')
            self.oOutput.Line('Timestamp: %d %s' % (timestamp, self.FormatTime(timestamp)))
            self.oOutput.Line('Data size: %d' % datasize)
            oStructData.Truncate(datasize)
            while oStructData.Length() > 0:
                command, argslen = oStructData.Unpack('>II')
                self.dCommandsSummary[command] = self.dCommandsSummary.get(command, 0) + 1
                self.oOutput.Line('Command: %d %s' % (command, self.LookupCommand(command)))
                if command == __class__.BEACON_COMMAND_SLEEP:
                    sleep, jitter = oStructData.Unpack('>II')
                    self.oOutput.Line(' Sleep: %d' % sleep)
                    self.oOutput.Line(' Jitter: %d' % jitter)
                elif command == __class__.BEACON_COMMAND_DATA_JITTER:
                    self.oOutput.Line(' Length random data = %d' % argslen)
                    payload = oStructData.GetBytes(argslen)
                elif command == __class__.BEACON_COMMAND_RUN:
                    self.oOutput.Line(' Command: %s' % oStructData.GetString('>I'))
                    self.oOutput.Line(' Arguments: %s' % oStructData.GetString('>I'))
                    self.oOutput.Line(' Integer: %d' % oStructData.Unpack('>H'))
                else:
                    self.oOutput.Line(' Arguments length: %d' % argslen)
                    if argslen > 0:
                        if command in [40, 62]:
                            oStructCommand = cStruct(oStructData.GetBytes(argslen))
                            self.oOutput.Line(' Unknown1: %d' % oStructCommand.Unpack('>I'))
                            self.oOutput.Line(' Unknown2: %d' % oStructCommand.Unpack('>I'))
                            self.oOutput.Line(' Pipename: %s' % oStructCommand.GetString('>I'))
                            self.oOutput.Line(' Command: %s' % oStructCommand.GetString('>I'))
                            self.oOutput.Line(' ' + repr(oStructCommand.GetBytes()))
                        else:
                            payload = oStructData.GetBytes(argslen)
                            self.oOutput.Line(' ' + repr(payload[:argslen])[:100])
                            self.oOutput.Line(' MD5: ' + hashlib.md5(payload).hexdigest())
                            self.ExtractPayload(payload)

        self.oOutput.Line('')

def AnalyzeCaptureHTTP(filename, options):
    oOutput = InstantiateCOutput(options)
    oCSParser = cCSParser(options.rawkey, options.hmacaeskeys, True, True, options.transform, options.extract, oOutput)
    dMethods = {}

    capture = pyshark.FileCapture(filename, display_filter=options.displayfilter, use_json=True, include_raw=True)
    for packet in capture:
        if not hasattr(packet, 'http'):
            continue

        if hasattr(packet.http, 'request') and packet.http.has_field('1\\r\\n'): # this is a bug in PyShark, should be fieldname request
            dMethods[packet.number] = packet.http.get_field('1\\r\\n').method

        data_raw = None
        if hasattr(packet.http, 'file_data_raw'):
            data_raw = packet.http.file_data_raw
        elif hasattr(packet.http, 'content-encoded_entity_body_(gzip)'):
            data_raw = getattr(packet.http, 'content-encoded_entity_body_(gzip)').data.data_raw
        else:
            continue

        if hasattr(packet.http, 'response'):
            oOutput.Line('Packet number: %d' % packet.number)
            if hasattr(packet.http, 'request_in') and len(packet.http.request_in.fields) > 0:
                requestPacket = packet.http.request_in.fields[0].int_value
                oOutput.Line('HTTP response (for request %d %s)' % (requestPacket, dMethods.get(requestPacket, '')))
            else:
                oOutput.Line('HTTP response')
            oCSParser.ProcessReplyPacketData(data_raw[0])

        if hasattr(packet.http, 'request'):
            oOutput.Line('Packet number: %d' % packet.number)
            oOutput.Line('HTTP request %s' % dMethods.get(packet.number, ''))
            oOutput.Line(packet.http.full_uri)
            oCSParser.ProcessPostPacketData(data_raw[0])

    capture.close()

    if len(oCSParser.dCommandsSummary) > 0:
        oOutput.Line('Commands summary:')
        for command, counter in sorted(oCSParser.dCommandsSummary.items()):
            oOutput.Line(' %d %s: %d' % (command, oCSParser.LookupCommand(command), counter))

    oOutput.Line('')

    if len(oCSParser.dCallbacksSummary) > 0:
        oOutput.Line('Callbacks summary:')
        for callback, counter in sorted(oCSParser.dCallbacksSummary.items()):
            oOutput.Line(' %d %s: %d' % (callback, oCSParser.LookupCallback(callback), counter))

def IsNumber(data):
    for a in data:
        if not a in '0123456789':
            return False
    return True

def IsHexNumber(data):
    for a in data.lower():
        if not a in '0123456789abcdef':
            return False
    return True

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

def EndsWithGetRemainder(strIn, strEnd):
    if strIn.endswith(strEnd):
        return True, strIn[:-len(strEnd)]
    else:
        return False, None

def IPv4ToHex(ipv4):
    return ''.join(['%02x' % int(number) for number in ipv4.split('.')])

class cParts(object):
    def __init__(self, dnsidle=''):
        if dnsidle == '':
            self.dnsidle = 0
        else:
            self.dnsidle = int(IPv4ToHex(dnsidle), 16)
        self.Init()

    def Init(self):
        self.dParts = {}
        self.size = None
        self.identifier = None

    def Add(self, counter, value):
        if counter.startswith('0'):
            self.identifier = counter[1:]
            self.size = int(self.Convert1(value), 16) ^ self.dnsidle
            self.dParts = {}
        elif self.identifier == None:
            self.Init()
        elif counter.endswith(self.identifier):
            self.dParts[int(counter, 16)] = value

    def Assemble(self):
        if self.identifier == None:
            return None
        numbers = sorted(self.dParts.keys())
        data = ''
        for number in numbers:
            data += ''.join(self.Convert2(self.dParts[number]))
        data = self.Convert3(data)
        if len(data) == self.size * 2:
            return data
        else:
            return None

class cPartsIPv4(cParts):
    @staticmethod
    def Convert1(data):
        return IPv4ToHex(data)

    @staticmethod
    def Convert2(data):
        return IPv4ToHex(data)

    @staticmethod
    def Convert3(data):
        return data

def IPv6ToHex(ipv6):
    return ipaddress.ip_address(ipv6).exploded.replace(':', '')

class cPartsIPv6(cParts):
    @staticmethod
    def Convert1(data):
        return IPv4ToHex(data)

    @staticmethod
    def Convert2(data):
        return IPv6ToHex(data)

    @staticmethod
    def Convert3(data):
        return data

class cPartsTXT(cParts):
    @staticmethod
    def Convert1(data):
        return IPv4ToHex(data)

    @staticmethod
    def Convert2(data):
        return data

    @staticmethod
    def Convert3(data):
        try:
            decoded = binascii.a2b_base64(data)
        except binascii.Error:
            return ''
        return binascii.b2a_hex(decoded).decode()

class cPartsLabels(cParts):
    @staticmethod
    def Convert1(data):
        return data[0][1:]

    @staticmethod
    def Convert2(data):
        return ''.join(data)[1:]

    @staticmethod
    def Convert3(data):
        return data

def CheckForBeacon(labels, dBeacons):
    for position, label in enumerate(labels):
        if label in dBeacons:
            return labels[:position]
    return None

def AnalyzeCaptureDNS(filename, options):
    oOutput = InstantiateCOutput(options)
    oCSParser = cCSParser(options.rawkey, options.hmacaeskeys, True, False, '', options.extract, oOutput)

    dBeacons = {}
    oPartsLabels = cPartsLabels()
    oPartsIPv4 = cPartsIPv4(options.dnsidle)
    oPartsIPv6 = cPartsIPv6(options.dnsidle)
    oPartsTXT = cPartsTXT(options.dnsidle)
    dPings = {}

    if options.beaconid != '':
        dBeacons[options.beaconid.lower()] = 'option'
    capture = pyshark.FileCapture(filename, display_filter=options.displayfilter, use_json=True)
    for packet in capture:
        if not hasattr(packet, 'dns'):
            continue

        if not hasattr(packet.dns, 'flags'):
            continue

        linePacket = 'Packet: %s %d' % (packet.sniff_time, packet.number)
        if int(packet.dns.flags, 16) & 0x8000 == 0x0000:
            if hasattr(packet.dns, 'Queries'):
                name = ''
                for shortname in packet.dns.Queries.field_names:
                    fullname = packet.dns.Queries.get_field(shortname).name
                    if len(fullname) > len(name):
                        name = fullname
                labels = name.split('.')
                if IsHexNumber(labels[0]) and int(labels[0], 16) & 0x4B2 == 0x4B2:
                    oOutput.Line(linePacket)
                    oOutput.Line('packet.dns.flags: %x' % int(packet.dns.flags, 16))
                    print('Beacon V4 ping found: %s' % name)
                    dBeacons[labels[0]] = 'V4'
                    dPings[packet.number] = True
                elif IsNumber(labels[0]):
                    oOutput.Line(linePacket)
                    oOutput.Line('packet.dns.flags: %x' % int(packet.dns.flags, 16))
                    print('Beacon V3 ping found: %s' % name)
                    dBeacons[labels[0]] = 'V3'
                else:
                    csquery = CheckForBeacon(labels, dBeacons)
                    if csquery != None:
                        if csquery == []:
                            pass
                        elif csquery[0] == 'www':
                            oOutput.Line(linePacket)
                            print('Beacon checkin: %s' % name)
                            oPartsLabels.Add(csquery[-1], csquery[1:-1])
                            encryptedMetadata = oPartsLabels.Assemble()
                            if encryptedMetadata != None:
                                print('encryptedMetadata: ' + encryptedMetadata)
                                print('encryptedMetadata BASE64: ' + binascii.b2a_base64(binascii.a2b_hex(encryptedMetadata)).decode())
                        elif csquery[0] in ['cdn', 'api']:
                            oOutput.Line(linePacket)
                            print('Beacon GET: %s' % name)
                        elif csquery[0] == 'post':
                            oOutput.Line(linePacket)
                            print('Beacon POST: %s' % name)
                            oPartsLabels.Add(csquery[-1], csquery[1:-1])
                            postData  = oPartsLabels.Assemble()
                            if postData != None:
                                print('-' * 100)
                                print('postData: ' + postData)
                                oCSParser.ProcessPostPacketData(postData)
                                print('-' * 100)
                print('')
            
        if int(packet.dns.flags, 16) & 0x8000 == 0x8000:
            if hasattr(packet.dns, 'Answers'):
                for name in packet.dns.Answers.field_names:
                    labels = name.split('.')
                    csquery = CheckForBeacon(labels, dBeacons)
                    if csquery != None:
                        if csquery == []:
                            if hasattr(packet.dns, 'response_to') and packet.dns.response_to.fields[0].int_value in dPings:
                                if hasattr(packet.dns.Answers.get_field(name), 'a'):
                                    if options.dnsidle == '':
                                        xormask = 0
                                    else:
                                        xormask = int(IPv4ToHex(options.dnsidle), 16)
                                    intIPv4 = int(IPv4ToHex(packet.dns.Answers.get_field(name).a), 16) ^ xormask
                                    if intIPv4 >= 240 and intIPv4 <= 255:
                                        oOutput.Line(linePacket)
                                        print('Reply to beacon V4 ping found: %d' % intIPv4)
                                        if intIPv4 & 1 == 1:
                                            print('Checkin requested')
                                        if intIPv4 & 0x0E == 0:
                                            print('mode dns')
                                        if intIPv4 & 0x0E == 2:
                                            print('mode dns-txt')
                                        if intIPv4 & 0x0E == 4:
                                            print('mode dns6')
                                        print('')
                        elif labels[0] == 'cdn':
                            oOutput.Line(linePacket)
                            oPartsIPv4.Add(csquery[-1], packet.dns.Answers.get_field(name).a)
                            print(packet.dns.Answers.get_field(name).name)
                            print(packet.dns.Answers.get_field(name).a)
                            replyData = oPartsIPv4.Assemble()
                            if replyData != None:
                                print('-' * 100)
                                print('replyData: ' + replyData)
                                oCSParser.ProcessReplyPacketData(replyData)
                                print('-' * 100)
                            print('')
                        elif labels[0] == 'api':
                            oOutput.Line(linePacket)
                            if hasattr(packet.dns.Answers.get_field(name), 'a'):
                                oPartsTXT.Add(csquery[-1], packet.dns.Answers.get_field(name).a)
                                print(packet.dns.Answers.get_field(name).a)
                            elif hasattr(packet.dns.Answers.get_field(name), 'txt'):
                                print('TXT record content: %s' % packet.dns.Answers.get_field(name).txt)
                                oPartsTXT.Add(csquery[-1], packet.dns.Answers.get_field(name).txt)
                                replyData = oPartsTXT.Assemble()
                                if replyData != None:
                                    print('-' * 100)
                                    print('replyData: ' + replyData)
                                    oCSParser.ProcessReplyPacketData(replyData)
                                    print('-' * 100)
                        elif labels[0] == 'www6':
                            oOutput.Line(linePacket)
                            if hasattr(packet.dns.Answers.get_field(name), 'a'):
                                oPartsIPv6.Add(csquery[-1], packet.dns.Answers.get_field(name).a)
                                print(packet.dns.Answers.get_field(name).a)
                            elif hasattr(packet.dns.Answers.get_field(name), 'aaaa'):
                                oPartsIPv6.Add(csquery[-1], packet.dns.Answers.get_field(name).aaaa)
                                replyData = oPartsIPv6.Assemble()
                                if replyData != None:
                                    print('-' * 100)
                                    print('replyData: ' + replyData)
                                    oCSParser.ProcessReplyPacketData(replyData)
                                    print('-' * 100)

    capture.close()

    if len(oCSParser.dCommandsSummary) > 0:
        oOutput.Line('Commands summary:')
        for command, counter in sorted(oCSParser.dCommandsSummary.items()):
            oOutput.Line(' %d %s: %d' % (command, oCSParser.LookupCommand(command), counter))

    oOutput.Line('')

    if len(oCSParser.dCallbacksSummary) > 0:
        oOutput.Line('Callbacks summary:')
        for callback, counter in sorted(oCSParser.dCallbacksSummary.items()):
            oOutput.Line(' %d %s: %d' % (callback, oCSParser.LookupCallback(callback), counter))

def AnalyzeCaptureCallback(hexdata, options):
    oOutput = InstantiateCOutput(options)
    oCSParser = cCSParser(options.rawkey, options.hmacaeskeys, True, True, '', options.extract, oOutput)
    oCSParser.ProcessPostPacketData(hexdata)

def AnalyzeCaptureCallbackSingle(hexdata, options):
    oOutput = InstantiateCOutput(options)
    oCSParser = cCSParser(options.rawkey, options.hmacaeskeys, True, False, '', options.extract, oOutput)
    oCSParser.ProcessPostPacketData(hexdata)

def AnalyzeCaptureTask(hexdata, options):
    oOutput = InstantiateCOutput(options)
    oCSParser = cCSParser(options.rawkey, options.hmacaeskeys, True, False, '', options.extract, oOutput)
    oCSParser.ProcessReplyPacketData(hexdata)

def AnalyzeCapture(filename, options):
    if options.displayfilter == '':
        options.displayfilter = options.format

    if options.format == 'http':
        AnalyzeCaptureHTTP(filename, options)
    elif options.format == 'dns':
        AnalyzeCaptureDNS(filename, options)
    elif options.format == 'callback':
        AnalyzeCaptureCallback(filename, options)
    elif options.format == 'callbacksingle':
        AnalyzeCaptureCallbackSingle(filename, options)
    elif options.format == 'task':
        AnalyzeCaptureTask(filename, options)
    else:
        raise Exception('Unknown format: %s' % options.format)

def ProcessArguments(arguments, options):
    for argument in arguments:
        AnalyzeCapture(argument, options)

def Main():
    moredesc = '''

Arguments:
@file: process each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]file ...]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file (# supported)')
    oParser.add_option('-f', '--format', type=str, default='http', help='Format: http/dns/task/callback/callbacksingle (default http)')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='Extract payloads to disk')
    oParser.add_option('-r', '--rawkey', type=str, default='', help="CS beacon's raw key")
    oParser.add_option('-k', '--hmacaeskeys', type=str, default='', help="HMAC and AES keys in hexadecimal separated by :")
    oParser.add_option('-Y', '--displayfilter', type=str, default='', help="Tshark display filter (default http/dns)")
    oParser.add_option('-t', '--transform', type=str, default='', help='Transformation instructions')
    oParser.add_option('-i', '--dnsidle', type=str, default='', help="DNS idle value")
    oParser.add_option('-b', '--beaconid', type=str, default='', help="Beacond ID (hexadecimal)")
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    ProcessArguments(args, options)

if __name__ == '__main__':
    Main()
