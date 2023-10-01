#!/usr/bin/env python

__description__ = 'TCP and UDP listener'
__author__ = 'Didier Stevens'
__version__ = '0.1.4'
__date__ = '2023/04/09'

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2018/03/08: start
  2018/03/09: continue
  2018/03/17: continue, added ssl
  2018/03/22: 0.0.2 added ssh
  2018/08/26: 0.0.3 added randomness when selecting a matching regular expression
  2018/09/09: added support for listeners via arguments
  2018/12/23: 0.0.4 added THP_SPLIT
  2019/03/12: added error handling
  2019/04/10: THP_STARTSWITH and THP_ELSE
  2019/05/30: 0.0.5 added File2String
  2019/07/11: 0.0.6 added error handling for oSocket.listen(5)
  2019/11/06: 0.0.7 added THP_ECHO
  2019/11/07: added option -f
  2019/11/09: updated man with THP_ECHO details
  2020/02/13: 0.1.0 Python 3 support; started integrating UDP listener
  2020/03/30: 0.1.1 added re.DOTALL to .search
  2020/05/30: renamed to simple_listener.py; switched source & destinations in log; added option dumpdata; added extra error handling for TLS untrusted certs
  2020/05/31: updated ports parsing to support UDP ports; added embedding of files
  2020/06/10: added THP_MINIMUM_DATA_LENGTH
  2020/11/16: added THP_READALL
  2020/11/21: removed hardcoded logfile names
  2021/01/25: added CONTENT_LENGTH
  2022/02/24: 0.1.2 changes to THP_ECHO class
  2022/02/25: updating man page; added # arguments
  2022/04/02: added value p (print) for option -f
  2022/04/12: bugfix
  2022/04/14: ReadBinaryFile
  2022/04/19: THP_DELAY; variables as command-line arguments; manual
  2022/04/28: added loglevel
  2022/04/29: added validate
  2022/07/07: added option --utcdatetime
  2022/09/02: 0.1.3 changed THP_READALL logic
  2023/01/19: added print lock; THP_ECHO_THIS; THP_ALLOW_LIST
  2023/03/16: man update for THP_ECHO_THIS
  2023/04/09: 0.1.4 added zip file support to ReadBinaryFile, added option --prompt

Todo:
  Add support for PyDivert
  Integrate https://github.com/ickerwx/tcpproxy ?
  Support starttls
  merge smtp-honeypot code?
  tool or function to create web server config
  tool or function to create webdav server config
  Let SendTCP check if all data was sent: check return value self.connection.send(data)
"""

#THP: TCP Honeypot
THP_REFERENCE = 'reference'
THP_SSL = 'ssl'
THP_CERTFILE = 'certfile'
THP_KEYFILE = 'keyfile'
THP_SSLCONTEXT = 'sslcontext'
THP_SSH = 'ssh'
THP_BANNER = 'banner'
THP_REPLY = 'reply'
THP_MATCH = 'match'
THP_LOOP = 'loop'
THP_REGEX = 'regex'
THP_STARTSWITH = 'startswith'
THP_ELSE = 'else'
THP_ACTION = 'action'
THP_DISCONNECT = 'disconnect'
THP_SPLIT = 'split'
THP_ECHO = 'echo'
THP_TCP = 'TCP'
THP_UDP = 'UDP'
THP_DATA = 'data'
THP_FILES = 'files'
THP_CONTENT = 'content'
THP_DESCRIPTION = 'description'
THP_MINIMUM_DATA_LENGTH = 'minimum_data_length'
THP_READALL = 'readall'
THP_DELAY = 'delay'
THP_ECHO_THIS = 'echo_this'
THP_ECHO_THIS_DELIMITER = 'echo_this_delimiter'
THP_ECHO_THIS_VARIABLE = 'echo_this_variable'
THP_ECHO_THIS_VARIABLE_DEFAULT = '%ECHOTHIS%'
THP_ECHO_THIS_FORMAT = 'echo_this_format'
THP_ECHO_THIS_FORMAT_RAW = 'echo_this_format_raw'
THP_ECHO_THIS_FORMAT_ESCAPED = 'echo_this_format_escaped'
THP_ECHO_THIS_FORMAT_BASE64 = 'echo_this_format_base64'
THP_ECHO_THIS_FORMAT_HEX = 'echo_this_format_hex'
THP_ECHO_THIS_FORMAT_DYNAMIC = 'echo_this_format_dynamic'
THP_ECHO_THIS_PERSIST = 'echo_this_persist'
THP_ALLOW_LIST = 'allow_list'

dumplinelength = 16

#Terminate With CR LF
def TW_CRLF(data):
    if isinstance(data, (str, bytes)):
        data = [data]
    return b'\r\n'.join(data + [b''])

dListeners = {
}

import optparse
import socket
import select
import threading
import time
import re
import ssl
import textwrap
import sys
import random
import traceback
import binascii
import struct
import inspect
import os.path
import ast
import hashlib
import calendar
if sys.version_info[0] >= 3:
    from io import StringIO
else:
    from cStringIO import StringIO
try:
    import paramiko
except:
    pass
try:
    import pyzipper as zipfile
except ImportError:
    import zipfile

def PrintManual():
    manual = r'''
Manual:

simple-listener is a tool that listens on TCP and UCP ports, opens connections when clients connect, and interacts with those clients.
This has to be configured via a Python dictionary called dListeners.

Listening ports can be configured with options -p or -P only, no need for a dictionary if you just need an open port.

For more interaction, configure listeners with the dListeners dictionary.
This dListeners dictionary is a global variable (Python), that can be modified/overwritten by executing Python scripts in the context of the simple-listener instance.
These Python scripts to execute are just passed on as arguments to simple-listener: each file provided as an argument, is executed as a Python script.

To open a port without a listener configuration, use option -p or -P.
Use the same notation as in nmap to provide ports: integers (x) or ranges of integers (y-z).
Like this: 4444,6000-6002
This opens TCP ports 4444, 6000, 6001 and 6002.
To open UDP ports, use prefix u:, like this: u:4444,u:6000-6002
Prefix t: can be used to open TCP ports, but it's optional. For legacy reasons (simple_listener is derived from tcp-honeypot), integers without prefix (t: or u:) represent TCP ports.
The difference between -P (--ports) and -p (--extraports) is the following: with -P, only ports defined via this option are opened for listening. All ports defined via dictionary dListeners are ignored.
With option -p, ports defined with dictionary dListeners are also opened for listening.

The keys in dictionary dListeners can be integers or strings.
Integers represent port numbers.
Strings represent templates, except when the string is THP_DATA ('data'). 'data' is a reserved keyword, explained later.

The value in a dictionary associated with a port (integer) can be the configuration of a TCP listener, a UDP listener or both.

Take the following example:

dListeners = {
    4444:   {THP_TCP: {THP_REPLY: b'Hello'}}
}

This dictionary defines a listener on TCP port 4444 that reads the data it receives, then sends back bytes b'Hello' and then closes the TCP connection.

This is a UDP listener example:

dListeners = {
    4444:   {THP_UDP: {THP_REPLY: b'Hello'}}
}

This dictionary defines a listener on UDP port 4444 that reads the data it receives, then sends back bytes b'Hello'.

And this is a TCP and UDP listener on the same port number:

dListeners = {
    4444:   {
             THP_TCP: {THP_REPLY: b'Hello TCP'},
             THP_UDP: {THP_REPLY: b'Hello UDP'}
            }
}

For legacy reasons, it is also possible to define a TCP listener without explicitly defining it as TCP:

dListeners = {
    4444:   {THP_REPLY: b'Hello'}
}

Of course, it is possible to define listeners on more than one port:

dListeners = {
    4444:   {
             THP_TCP: {THP_REPLY: b'Hello TCP 4444'},
             THP_UDP: {THP_REPLY: b'Hello UDP 4444'}
            },
    8080:   {
             THP_TCP: {THP_REPLY: b'Hello TCP 8080'},
             THP_UDP: {THP_REPLY: b'Hello UDP 8080'}
            }
}


TCP and UDP listeners are configured inside Python dictionary dListeners with another dictionary (listener dictionary).

Configuration options of a TCP listener:
When the listener dictionary is empty, the simple listener will accept TCP connections on the configured port, perform a single read and then close the connection.

Example:

dListeners = {
    4444:   {THP_TCP: {}}
}

The listener can be configured to perform more than one read: add key THP_LOOP to the dictionary with an integer as value. The integer specifies the maximum number of reads.

Example:

dListeners = {
    4444:   {THP_TCP: {THP_LOOP: 5}}
}

A banner can be transmitted before the first read, this is done by adding key THP_BANNER to the dictionary with a bytes string as the value (the banner).
The listener can be configured to send a reply after each read, this is done by adding key THP_REPLY to the dictionary with a bytes string as the value (the reply).

Example:

dListeners = {
    4444:   {THP_TCP: {THP_BANNER: b'Welcome'}}
}

To increase the interactivity of the simple listener, keywords can be defined with replies. This is done by adding a new dictionary to the dictionary with key THP_MATCH.
Entries in this match dictionary are strings that match the beginning of the data received (THP_STARTSWITH) or regular expressions (THP_REGEX). This is exclusive, the dictionary can not contain both THP_STARTSWITH and THP_REGEX entries.

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {'HELLO': {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'}}}}
}

'HELLO' is just an identifier for the matching dictionary, it can be any string. The match dictionary has 2 entries:
 THP_STARTSWITH: b'hello'
 THP_REPLY: b'hi there!'

If the data read starts with b'hello' (case-sensitive), then the reply b'hi there!' is sent back.
If the data doesn't match, then nothing is sent back: the connection is closed.
Several match dictionaries can be defined, to match different inputs:

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {
                                   'HELLO': {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':   {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'}
                                  }
                      }
            }
}

It is also possible to define a reply to be sent back when no input matches, this is done with THP_ELSE, like this:

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {
                                   'HELLO':    {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

Actions can also be executed in case of a match, in stead of sending back data (THP_REPLY).
This is defined with THP_ACTION, and the only action that is defined in this version, is to close the connection: THP_DISCONNECT.
This disconnection action only makes sence when a loop (THP_LOOP) is defined.

dListeners = {
    4444:   {THP_TCP: {THP_LOOP: 10,
                       THP_MATCH: {
                                   'HELLO':    {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'},
                                   'EXIT':     {THP_STARTSWITH: b'exit', THP_ACTION: THP_DISCONNECT},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

It is also possible to combine a reply and an action:

dListeners = {
    4444:   {THP_TCP: {THP_LOOP: 10,
                       THP_MATCH: {
                                   'HELLO':    {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'},
                                   'EXIT':     {THP_STARTSWITH: b'exit', THP_REPLY: b'closing connection!', THP_ACTION: THP_DISCONNECT},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

In stead of matching starts of data, regular expressions can be used to match incoming data: THP_REGEX.
When a regular expression matches read data, the corresponding reply is send or action performed (e.g. disconnect).
If more than one regular expression matches, then the longest matching is selected. If there is more than one longest match (e.g. equal length), then one is selected at random.
Regex matching is case sensitive.

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {
                                   'HELLO':    {THP_REGEX: b'^hello\n$', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_REGEX: b'^bye\n$', THP_REPLY: b'see you later!'}
                                  }
                      }
            }
}

THP_ELSE is supported too:

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {
                                   'HELLO':    {THP_REGEX: b'^hello\n$', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_REGEX: b'^bye\n$', THP_REPLY: b'see you later!'},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

Data sent back via THP_REPLY for example, is static: it is defined when the listeners dictionary is evaluated by Python. In stead of providing literal bytes strings, it is also possible to provide any Python expression that can be the value of a dictionary.
Helper function TW_CRLF (Terminate With CR/LF) can be used to format replies and banners. It takes a list of bytes strings as argument, terminates each string with CR/LF and concatenates them all into one bytes string.
Replies and banners can contain aliases: %TIME_GMT_RFC2822%, %TIME_GMT_EPOCH% and %CONTENT_LENGTH%, they will be instantiated when a reply is transmitted.
To manipulate the time represented by the %TIME_GMT_* variables, use option --utcdatetime.
Use this option to provide the "clock" this tool should use when instantiating these variables.
For example, option "--utcdatetime 2019-10-15T14:00:00" will let this tool assume that it was started on 2019/10/15 at 14:00:00 UTC.

dListeners = {
    4444:   {THP_TCP: {THP_MATCH: {
                                   'HELLO':    {THP_REGEX: b'^hello\n$', THP_REPLY: TW_CRLF([b'hi there!', b'It is %TIME_GMT_RFC2822%'])},
                                   'BYE':      {THP_REGEX: b'^bye\n$', THP_REPLY: b'see you later!'},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

THP_ECHO can be used to send back any incoming data (echo). Like this:

dListeners = {
    4444:   {THP_TCP: {
                       THP_LOOP: 5,
                       THP_ECHO: None
                      }
            }
}

THP_ECHO also takes a function, which's goal is to transform the incoming data and return it. Here is an example with a lambda function that converts all lowercase letters to uppercase:

dListeners = {
    4444:   {THP_TCP: {
                       THP_LOOP: 5,
                       THP_ECHO: lambda x: x.upper()
                      }
            }
}

THP_ECHO also takes a class.

If persistence is required across function calls, a custom class can also be provided. This class has to implement a method with name Process (input: incoming data, output: transformed data).

For example:

class MyEcho():
    def __init__(self, oOutput):
        self.counter = 0
        self.oOutput = oOutput

    def Process(self, data):
        self.counter += 1
        return b'Counter %d: %s\n' % (self.counter, repr(data).encode())

dListeners = {
    4444:   {THP_TCP: {
                       THP_LOOP: 5,
                       THP_ECHO: MyEcho
                      }
            }
}

This can be used to make more complex listeners.

THP_ECHO_THIS can be used to configure a listener that will send a reply depending on the content of the query. In a nutshell: with THP_ECHO_THIS, is is possible to encode the reply somewhere inside the request, and then the listener will extract the reply and send it to the client.
THP_ECHO_THIS is used together with THP_REPLY and/or THP_MATCH.

THP_ECHO_THIS requires one mandatory configuration item: THP_ECHO_THIS_DELIMITER. Let's illustrate with an example:

dListeners = {
    4444:   {THP_TCP: {
                       THP_ECHO_THIS: {THP_ECHO_THIS_DELIMITER: 'ECHOTHIS'},
                       THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK', b'Date: %TIME_GMT_RFC2822%', b'Content-Length: %CONTENT_LENGTH%', b'']) + b'<html>Hello %ECHOTHIS%!</html>'
                      }
            }
}

If we run this listener and issue the following curl command:

curl -H "X-Something: ECHOTHISDidierECHOTHIS" http://127.0.0.1:4444

Then we will get this HTML page:
<html>Hello Didier!</html>

It works as follows: our HTTP GET request done with curl, includes a custom header: X-Something: ECHOTHISDidierECHOTHIS.
Our listener looks at the raw input (not only the headers), and searches for delimiter ECHOTHIS (specified via THP_ECHO_THIS_DELIMITER). If it finds two instances of this delimiter, it will take all the bytes between these delimiters (Didier) and store this into variable %ECHOTHIS%.
Then this variable can be used in the reply.

By default, the name of the variable is %ECHOTHIS%, but this can be changed with configuration item THP_ECHO_THIS_VARIABLE.
The data that is stored inside this variable, is taken from the raw request: its the bytes delimited by the first and second instance of the delimiter (ECHOTHIS by default).
By default, these bytes are not interpreted, they are taken as is. This behavior can be changed with configuration item THP_ECHO_THIS_FORMAT. This configuration item can be set to the following values:

THP_ECHO_THIS_FORMAT_RAW (default)
THP_ECHO_THIS_FORMAT_BASE64
THP_ECHO_THIS_FORMAT_HEX
THP_ECHO_THIS_FORMAT_ESCAPED
THP_ECHO_THIS_FORMAT_DYNAMIC

THP_ECHO_THIS_FORMAT_BASE64 means that the bytes are base64-decoded before being stored in the variable.
THP_ECHO_THIS_FORMAT_HEX means that the bytes are hex-decoded before being stored in the variable.
THP_ECHO_THIS_FORMAT_ESCAPED means that the bytes are interpreted as a Python string with escape characters (like \\n).
THP_ECHO_THIS_FORMAT_DYNAMIC means that it is the client that decides on the format, not the listener. In dynamic mode, the content must be preceded by a letter that specifies which encoding is used:

R: THP_ECHO_THIS_FORMAT_RAW
B: THP_ECHO_THIS_FORMAT_BASE64
H: THP_ECHO_THIS_FORMAT_HEX
E: THP_ECHO_THIS_FORMAT_ESCAPED

Here is an example:

dListeners = {
    4444:   {THP_TCP: {
                       THP_ECHO_THIS: {THP_ECHO_THIS_DELIMITER: 'ECHOTHIS', THP_ECHO_THIS_FORMAT: THP_ECHO_THIS_FORMAT_DYNAMIC},
                       THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK', b'Date: %TIME_GMT_RFC2822%', b'Content-Length: %CONTENT_LENGTH%', b'']) + b'ECHOTHIS%'
                      }
            }
}

If we run this listener and issue the following curl command:

curl -H "X-Something: ECHOTHISH414141410D0AECHOTHIS" http://127.0.0.1:4444

Then we will get this:
AAAA

The message encode in the header of the query is H414141410D0A. Since we configured a dynamic format (THP_ECHO_THIS_FORMAT_DYNAMIC), the listener takes the first letter of the message (H) and then interprets the rest of the messages as hexadecimal, yielding AAAA\r\n.

Finally, it is possible to prefix this message with one more letter (P for persist) to persist the message between requests.

If we run the same listener and issue the following curl command:

curl -H "X-Something: ECHOTHISPH414141410D0AECHOTHIS" http://127.0.0.1:4444

Then we will get this:
AAAA

Exactly the same result as in the previous example.
But this time, the listener also remembers the message (persist) because of the P prefix: PH414141410D0A. If we issue a request without message, then we will still get our message:

curl http://127.0.0.1:4444

Gives this:
AAAA


This will remain the reply to any query, until a new query with a message is performed, or until the listener is stopped.


Configuration item THP_DELAY introduces a delay (expressed in seconds, use floating number for milliseconds) before each reply. This can be used to simulate timeouts, for example.

dListeners = {
    4444:   {THP_TCP: {THP_DELAY: 3.5, THP_BANNER: b'Welcome'}}
}

In this example, a delay of 3.5 seconds is introduced before the banner is send.

When input has to be split by a separator before processing, THP_SPLIT can be used:

dListeners = {
    4444:   {THP_TCP: {THP_SPLIT: b',',
                       THP_MATCH: {
                                   'HELLO':    {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

In this example, the comma (b',') is a separator. Input like 'hello,lala,bye' is split up into 'hello' 'lala' 'bye' and then processed part per part.

Sometimes, input data needs a minimum length for processing to start. This can be configured with THP_MINIMUM_DATA_LENGTH.

And a listener can also be configure to read all data until there is no more data ready, before processing starts (experimental feature). This is done with THP_READALL.
Value True enables this, but one can also provide an integer or floating point number. That number is used as a delay (seconds) between each read (recv).

dListeners = {
    4444:   {THP_TCP: {THP_READALL: 0.1,
                       THP_MATCH: {
                                   'HELLO':    {THP_STARTSWITH: b'hello', THP_REPLY: b'hi there!'},
                                   'BYE':      {THP_STARTSWITH: b'bye', THP_REPLY: b'see you later!'},
                                   'FALLBACK': {THP_ELSE: None, THP_REPLY: b'I did not understand that!'}
                                  }
                      }
            }
}

A listener can have a description: THP_DESCRIPTION. This information is not processed, just stored.

A listener can be configured to accept SSL/TLS connections by adding key THP_SSL to the listener dictionary with a dictionary as value specifying the certificate (THP_CERTFILE) and key (THP_KEYFILE) to use. If an SSL context can not be created (for example because of missing certificate file), the listener will fallback to TCP.

Example:

dListeners = {
    4444:   {THP_TCP: {
                       THP_SSL: {THP_CERTFILE: 'cert-20180317-161753.crt', THP_KEYFILE: 'key-20180317-161753.pem'},
                       THP_LOOP: 5,
                       THP_ECHO: None
                      }
            }
}


Files cert-20180317-161753.crt and key-20180317-161753.pem are read from disk. They can also be included in the dListeners dictionary (see later).

A listener can be configured to accept SSH connections by adding key THP_SSH to the listener dictionary with a dictionary as value specifying the key (THP_KEYFILE) to use. This requires Python module paramiko, the listener will fallback to TCP if this module is missing.
If no keyfile is provided, an RSA key is generated for this listener.

Example:

dListeners = {
    4444:   {THP_TCP: {
                       THP_SSH: {THP_KEYFILE: 'test_rsa.key', THP_BANNER: 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2'},
                       THP_BANNER: TW_CRLF(b'Last login: Thu Mar 22 18:10:31 2018 from 192.168.1.1') + b'root@vps:~# ',
                       THP_REPLY: b'\r\nroot@vps:~# ',
                       THP_LOOP: 5
                      }
            }
}

There are 2 banners defined here: one is the banner before the SSH handshake, the other banner is sent after the SSH connection is established.

Certificate files and key files used foor SSL/TLS & SSH connections, can be included in the dListeners dictionary, and are written to disk when needed.
This is done by creating a key THP_DATA with a value that is a dictionary. This dictionary contains a key THP_FILE with another dictionary as value.

Then each file can be embedded with their filename and content (THP_CONTENT), like this:

    THP_DATA: {THP_FILES: {
                            'cert-20180317-161753.crt': {THP_CONTENT:
"""-----BEGIN CERTIFICATE-----
MIIE3jCCAsYCAQEwDQYJKoZIhvcNAQELBQAwNTELMAkGA1UEBhMCVVMxEDAOBgNV
...
iDM=
-----END CERTIFICATE-----
"""
                                                        },
                            'key-20180317-161753.pem': {THP_CONTENT:
"""-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDEdKSlZSQuXhsY
...
CtDpEOHKFyN/by2NAzByMyixR/A4Zhw=
-----END PRIVATE KEY-----
"""
                                                        },
                            'test_rsa.key': {THP_CONTENT:
"""-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQDTj1bqB4WmayWNPB+8jVSYpZYk80Ujvj680pOTh2bORBjbIAyz
...nvuQES5C9BMHjF39LZiGH1iLQy7FgdHyoP+eodI7
-----END RSA PRIVATE KEY-----
"""
                                                        },
                          }},

With this configuration item, the files are embedded inside the configuration dictionary dListeners. When one of these files is referenced in a listener configuration (SSL/TLS/SSH), and the file does not exist on disk, then it is written to disk with name and content found in this THP_DATA configuration item.

A listener can be configured to restrict replies to a list of allowed clients (source IPs). This is done with configuration item THP_ALLOW_LIST.

Example:

dListeners = {
    4444:   {THP_TCP: {THP_ALLOW_LIST: ['192.168.0.10'], THP_REPLY: b'Hello'}}
}

When several ports need to behave the same, the dictionary can just contain a reference (THP_REFERENCE) to the port which contains the detailed description.

Example:

dListeners = {
    4444:   {THP_TCP: {THP_REPLY: b'Hello'}},
    8888:   {THP_TCP: {THP_REFERENCE: 4444}}
}

This configuration defines a listener on port 4444, that just sends an Hello reply. And another listener on port 8888, that uses the same configuration as for port 4444.

Listeners can also be templates: then they have a string as key, in stead of an integer (port number).

Example for a trivial HTTP server:

dListeners = {
    'HTTPWELCOME': {THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK', b'Date: %TIME_GMT_RFC2822%', b'Server: Apache', b'Last-Modified: Wed, 06 Jul 2016 17:51:03 GMT', b'ETag: "59652-cfd-edc33a50bfec6"', b'Accept-Ranges: bytes', b'Content-Length: %CONTENT_LENGTH%', b'Connection: close', b'Content-Type: text/html; charset=UTF-8', b'', b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">', b'<link rel="icon" type="image/png" href="favicon.png"/>', b'<html>', b'  <head>', b'    <title>Home</title>', b'    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">', b'  </head>', b'  <body>Welcome home!</body>', b'</html>'])}
}

When this configuration is executed, no port is opened, since there is no port defined in the configuration.
But this template can be used to open ports with this configuration.
This template can be referenced with options -p and -P, like this:

simple_listener.py -P 8080=HTTPWELCOME examples.py

TCP port 8080 is opened, and the listener of template HTTPWELCOME is defined for this port.

This template can also be referenced in the configuration file itself:

dListeners = {
    'HTTPWELCOME': {THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK', b'Date: %TIME_GMT_RFC2822%', b'Server: Apache', b'Last-Modified: Wed, 06 Jul 2016 17:51:03 GMT', b'ETag: "59652-cfd-edc33a50bfec6"', b'Accept-Ranges: bytes', b'Content-Length: %CONTENT_LENGTH%', b'Connection: close', b'Content-Type: text/html; charset=UTF-8', b'', b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">', b'<link rel="icon" type="image/png" href="favicon.png"/>', b'<html>', b'  <head>', b'    <title>Home</title>', b'    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">', b'  </head>', b'  <body>Welcome home!</body>', b'</html>'])},
    8080: {THP_TCP: {THP_REFERENCE: 'HTTPWELCOME'}}
}


These command-line arguments of this tool are filenames of Python programs that define listeners (these Python programs are executed in the context of the tool), or are definitions of variables or listeners.

All definition arguments have to start with # (filenames can not start with #).

To define the complete dListeners dictionary via a command-line argument, use #m# (m stands for "main listeners configuration").
Like this:

simple_listener.py "#m#{4444: {THP_TCP: {THP_ECHO: None}}}"

To add additional listeners via a command-line argument, use #a# (a stands for "additional listeners").

simple_listener.py "#a#{4444: {THP_TCP: {THP_ECHO: None}}}"

"Variables" can also be defined via a command line argument: use #v#.

Example:

simple_listener.py #v#FILETOSERVE=malware.vir

This defines key 'FILETOSERVE' with value 'malware.vir' in dictionary dVariables.
This can then be used with a configuration like this:

FILECONTENTTOSERVE = ReadBinaryFile(dVariables.get('FILETOSERVE', ''))

dListeners = {
    'HTTPSERVEFILE': {
                      THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK', b'Date: %TIME_GMT_RFC2822%', b'Content-Length: %CONTENT_LENGTH%', b'']) + FILECONTENTTOSERVE
                     },
}

simple_listener.py #v#FILETOSERVE=malware.vir httpservefile.py

If function ReadBinaryFile receives a filename that starts with #z#, the function will handle the file as a ZIP file and extract the first files from the ZIP container. If the file is password protected, password infected will be used.

Use option --prompt to prompt the user that launched this program after each request.
When this option is enabled, a prompt will be displayed one second after the processing of a request has started. This stops the processing of all new requests, until the user has provided an answer.
Answer s (letter s + ENTER key) stops the program, any other answer resumes processing.

Output is written to stdout and a log file.

Option -f (format) can be used to change the output format of data.
Possible values are: repr, x, X, a, A, b, B
The default value (repr) output's data on a single line using Python's repr function.
a is an ASCII/HEX dump over several lines, A is an ASCII/HEX dump too, but with duplicate lines removed.
x is an HEX dump over several lines, X is an HEX dump without whitespace.
b is a BASE64 dump over several lines, B is a BASE64 without whitespace.

Option -t can be used to change the timeout.

Option -d can be used to dump the sent data to file.

Option -r can be used to define the read buffer size.

Option -a can be used to define the address to listen on.

By default, everything is logged to the console and to the log file.
This is loglevel 1.
To restrict logging to the console to the startup phase only, use option --loglevel 2.
All startup messages like opening of ports will be logged to the console, but no log messages regarding connections.
With --loglevel 2, everything is logged to the log file.

Use option --validate to execute the program and all provided configuration and scripts, with opening of ports, but then stop the program before incoming data is processed.
This can help validate your configurations and scripts.

This tool is written for Python 3 and was tested on Windows 10 and Ubuntu 16/18/20.

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line, 79))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

#Convert 2 Integer If Python 2
def C2IIP2(data):
    if sys.version_info[0] > 2:
        return data
    else:
        return ord(data)

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def PrefixIfNeeded(string, prefix=' '):
    if string == '':
        return string
    else:
        return prefix + string

class cDump():
    def __init__(self, data, prefix='', offset=0, dumplinelength=16):
        self.data = data
        self.prefix = prefix
        self.offset = offset
        self.dumplinelength = dumplinelength

    def HexDump(self):
        oDumpStream = self.cDumpStream(self.prefix)
        hexDump = ''
        for i, b in enumerate(self.data):
            if i % self.dumplinelength == 0 and hexDump != '':
                oDumpStream.Addline(hexDump)
                hexDump = ''
            hexDump += IFF(hexDump == '', '', ' ') + '%02X' % self.C2IIP2(b)
        oDumpStream.Addline(hexDump)
        return oDumpStream.Content()

    def CombineHexAscii(self, hexDump, asciiDump):
        if hexDump == '':
            return ''
        countSpaces = 3 * (self.dumplinelength - len(asciiDump))
        if len(asciiDump) <= self.dumplinelength / 2:
            countSpaces += 1
        return hexDump + '  ' + (' ' * countSpaces) + asciiDump

    def HexAsciiDump(self, rle=False):
        oDumpStream = self.cDumpStream(self.prefix)
        position = ''
        hexDump = ''
        asciiDump = ''
        previousLine = None
        countRLE = 0
        for i, b in enumerate(self.data):
            b = self.C2IIP2(b)
            if i % self.dumplinelength == 0:
                if hexDump != '':
                    line = self.CombineHexAscii(hexDump, asciiDump)
                    if not rle or line != previousLine:
                        if countRLE > 0:
                            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
                        oDumpStream.Addline(position + line)
                        countRLE = 0
                    else:
                        countRLE += 1
                    previousLine = line
                position = '%08X:' % (i + self.offset)
                hexDump = ''
                asciiDump = ''
            if i % self.dumplinelength == self.dumplinelength / 2:
                hexDump += ' '
            hexDump += ' %02X' % b
            asciiDump += IFF(b >= 32 and b < 128, chr(b), '.')
        if countRLE > 0:
            oDumpStream.Addline('* %d 0x%02x' % (countRLE, countRLE * self.dumplinelength))
        oDumpStream.Addline(self.CombineHexAscii(position + hexDump, asciiDump))
        return oDumpStream.Content()

    def Base64Dump(self, nowhitespace=False):
        encoded = binascii.b2a_base64(self.data)
        if nowhitespace:
            return encoded
        oDumpStream = self.cDumpStream(self.prefix)
        length = 64
        for i in range(0, len(encoded), length):
            oDumpStream.Addline(encoded[0+i:length+i])
        return oDumpStream.Content()

    class cDumpStream():
        def __init__(self, prefix=''):
            self.oStringIO = StringIO()
            self.prefix = prefix

        def Addline(self, line):
            if line != '':
                self.oStringIO.write(self.prefix + line + '\n')

        def Content(self):
            return self.oStringIO.getvalue()

    @staticmethod
    def C2IIP2(data):
        if sys.version_info[0] > 2:
            return data
        else:
            return ord(data)

def HexDump(data):
    return cDump(data, dumplinelength=dumplinelength).HexDump()

def HexAsciiDump(data, rle=False):
    return cDump(data, dumplinelength=dumplinelength).HexAsciiDump(rle=rle)

def Base64Dump(data, nowhitespace=False):
    return cDump(data, dumplinelength=dumplinelength).Base64Dump(nowhitespace=nowhitespace)

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

def FormatTime(epoch=None):
    if epoch == None:
        epoch = time.time()
    return '%04d%02d%02d-%02d%02d%02d' % time.localtime(epoch)[0:6]

class cOutput():
    def __init__(self, filename=None, bothoutputs=False):
        self.filename = filename
        self.bothoutputs = bothoutputs
        self.oLock = threading.Lock()
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        self.oLock.acquire()
        if not self.f or self.bothoutputs:
            print(line)
        if self.f:
            try:
                self.f.write(line + '\n')
                self.f.flush()
            except:
                pass
        self.oLock.release()

    def LineTimestamped(self, line):
        self.Line('%s: %s' % (FormatTime(), line))

    def Exception(self):
        self.LineTimestamped('Exception occured:')
        if not self.f or self.bothoutputs:
            traceback.print_exc()
        if self.f:
            try:
                traceback.print_exc(file=self.f)
                self.f.flush()
            except:
                pass

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

def GetContent(data):
    MARKER = b'\r\n\r\n'
    position = data.find(MARKER)
    if position == -1:
        return b''
    else:
        return data[position + len(MARKER):]

def ReplaceAliases(data, dVariables={}):
    global epochOffset

    now = time.time()
    now = now + epochOffset

    for key, value in dVariables.items():
        data = data.replace(key, value)
    data = data.replace(b'%TIME_GMT_RFC2822%', time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(now)).encode())
    data = data.replace(b'%TIME_GMT_EPOCH%', str(int(now)).encode())

    CONTENT_LENGTH = b'%CONTENT_LENGTH%'
    if CONTENT_LENGTH in data:
        data = data.replace(CONTENT_LENGTH, str(len(GetContent(data))).encode())
    return data

def MyStartsWith(string, prefix):
    if string.startswith(prefix):
        return True, string[len(prefix):]
    else:
        return False, string

def ParseNumber(number):
    result, number = MyStartsWith(number, '0x')
    if result:
        return int(number, 16)
    else:
        return int(number)

def ParsePort(number):
    protocol = THP_TCP
    result, number = MyStartsWith(number, 't:')
    if not result:
        result, number = MyStartsWith(number, 'u:')
        if result:
            protocol = THP_UDP
    reference = None
    result = number.split('=', 1)
    if len(result) == 2:
        number, reference = result
    return protocol, ParseNumber(number), reference

def MyRange(begin, end):
    begin_protocol, begin_port, begin_reference = begin
    end_protocol, end_port, end_reference = end
    if begin_port < end_port:
        return [[begin_protocol, port, begin_reference] for port in range(begin_port, end_port + 1)]
    elif begin_port == end_port:
        return [begin]
    else:
        return [[begin_protocol, port, begin_reference] for port in range(begin_port, end_port - 1, -1)]

def ParsePorts(expression):
    ports = []
    for portrange in expression.split(','):
        result = portrange.split('-')
        if len(result) == 1:
            ports.append(ParsePort(result[0]))
        else:
            ports.extend(MyRange(ParsePort(result[0]), ParsePort(result[1])))
    return ports

def ModuleLoaded(name):
    return name in sys.modules

if ModuleLoaded('paramiko'):
    class cSSHServer(paramiko.ServerInterface):
        def __init__(self, oOutput, connectionID):
            self.oEvent = threading.Event()
            self.oOutput = oOutput
            self.connectionID = connectionID

        def check_channel_request(self, kind, chanid):
            if kind == 'session':
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            self.oOutput.LineTimestamped('%s SSH username: %s' % (self.connectionID, username))
            self.oOutput.LineTimestamped('%s SSH password: %s' % (self.connectionID, password))
            return paramiko.AUTH_SUCCESSFUL

        def get_allowed_auths(self, username):
            return 'password'

        def check_channel_shell_request(self, channel):
            self.oEvent.set()
            return True

        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
            return True

def SplitIfRequested(dListener, data):
    if THP_SPLIT in dListener:
        return [part for part in data.split(dListener[THP_SPLIT]) if part != b'']
    else:
        return [data]

def GetListener(port, protocol=THP_TCP):
    global dListeners

    reference = ''
    if not isinstance(port, int):
        return None, reference
    dListener = dListeners[port]
    if THP_TCP in dListener.keys() or THP_UDP in dListener.keys():
        dListener = dListener.get(protocol, None)
        if dListener == None:
            return dListener, reference
    elif protocol == THP_UDP:
        return None, reference
    if THP_REFERENCE in dListener:
        if isinstance(dListener[THP_REFERENCE], str):
            reference = dListener[THP_REFERENCE]
        dListener = dListeners[dListener[THP_REFERENCE]]
    if THP_TCP in dListener.keys() or THP_UDP in dListener.keys():
        dListener = dListener.get(protocol, None)
    return dListener, reference

def String2File(string, filename):
    try:
        f = open(filename, 'w')
    except:
        return None
    try:
        return f.write(string)
    finally:
        f.close()

def ExportFile(filename):
    global dListeners

    if not THP_DATA in dListeners:
        return

    if not THP_FILES in dListeners[THP_DATA]:
        return

    if not filename in dListeners[THP_DATA][THP_FILES]:
        return

    if os.path.exists(filename):
        return

    String2File(dListeners[THP_DATA][THP_FILES][filename][THP_CONTENT], filename)

class cConnectionThread(threading.Thread):
    def __init__(self, oSocket, oOutput, options):
        threading.Thread.__init__(self)
        self.oSocket = oSocket
        self.oOutput = oOutput
        self.options = options
        self.connection = None
        self.connectionID = None
        self.protocol = None

    def run(self):
        if self.oSocket.type == socket.SocketKind.SOCK_STREAM:
            self.RunTCP()
        elif self.oSocket.type == socket.SocketKind.SOCK_DGRAM:
            self.RunUDP()

    def CheckAllowList(self, address=None):
        if address == None:
            return THP_ALLOW_LIST in self.dListener
        return address in self.dListener[THP_ALLOW_LIST]

    def EchoThis(self, data):
        dVariables = {}
        message = None
        if THP_ECHO_THIS in self.dListener:
            delimiter = self.dListener[THP_ECHO_THIS][THP_ECHO_THIS_DELIMITER].encode('latin')
            variable = self.dListener[THP_ECHO_THIS].get(THP_ECHO_THIS_VARIABLE, THP_ECHO_THIS_VARIABLE_DEFAULT).encode('latin')
            position1 = data.find(delimiter)
            if position1 != -1:
                position2 = data.find(delimiter, position1 + 1)
            else:
                position2 = -1
            if position2 != -1:
                message = data[position1 + len(delimiter):position2]
        if message != None:
            persist = False
            format = self.dListener[THP_ECHO_THIS].get(THP_ECHO_THIS_FORMAT, THP_ECHO_THIS_FORMAT_RAW)
            if format == THP_ECHO_THIS_FORMAT_DYNAMIC:
                if message[0:1] == b'P':
                    persist = True
                    message = message[1:]
                format = {
                    b'B': THP_ECHO_THIS_FORMAT_BASE64,
                    b'E': THP_ECHO_THIS_FORMAT_ESCAPED,
                    b'R': THP_ECHO_THIS_FORMAT_RAW,
                    b'H': THP_ECHO_THIS_FORMAT_HEX,
                }[message[0:1]]
                message = message[1:]
            if format == THP_ECHO_THIS_FORMAT_RAW:
                pass
            elif format == THP_ECHO_THIS_FORMAT_BASE64:
                message = binascii.a2b_base64(message)
            elif format == THP_ECHO_THIS_FORMAT_HEX:
                message = binascii.a2b_hex(message)
            elif format == THP_ECHO_THIS_FORMAT_ESCAPED:
                message = ast.literal_eval('"""' + message.decode() + '"""').encode('latin')
            dVariables[variable] = message
            if persist:
                self.dListener[THP_ECHO_THIS_PERSIST] = message
        elif THP_ECHO_THIS_PERSIST in self.dListener:
            dVariables[variable] = self.dListener[THP_ECHO_THIS_PERSIST]

        return dVariables

    def RunTCP(self):
        self.protocol = THP_TCP
        oSocketConnection, address = self.oSocket.accept()
        self.connectionID = '%s:%d-%s:%d' % (address + self.oSocket.getsockname())
        oSocketConnection.settimeout(self.options.timeout)
        self.oOutput.LineTimestamped('%s TCP connection' % self.connectionID)
        self.dListener, dummy = GetListener(self.oSocket.getsockname()[1])
        if self.CheckAllowList():
            if self.CheckAllowList(address[0]):
                self.oOutput.LineTimestamped('%s %s %s on allowlist' % (self.connectionID, self.protocol, address[0]))
            else:
                self.oOutput.LineTimestamped('%s %s %s not on allowlist' % (self.connectionID, self.protocol, address[0]))
                oSocketConnection.shutdown(socket.SHUT_RDWR)
                oSocketConnection.close()
                self.oOutput.LineTimestamped('%s %s closed' % (self.connectionID, self.protocol))
                return
        previous = b''
        try:
            oSSLConnection = None
            oSSLContext = self.dListener.get(THP_SSLCONTEXT, None)
            oSSHConnection = None
            oSSHFile = None
            if oSSLContext != None:
                oSSLConnection = oSSLContext.wrap_socket(oSocketConnection, server_side=True, do_handshake_on_connect=False)
                try:
                    oSSLConnection.do_handshake()
                except (ssl.SSLZeroReturnError, ssl.SSLError) as e:
                    if e.strerror.startswith('TLS/SSL connection has been closed (EOF)') or e.strerror.startswith('[SSL: SSLV3_ALERT_CERTIFICATE_UNKNOWN]'):
                        self.oOutput.LineTimestamped('%s TCP SSL closed' % self.connectionID)
                        oSSLConnection.shutdown(socket.SHUT_RDWR)
                        oSSLConnection.close()
                        oSSLConnection = None
                    else:
                        self.oOutput.LineTimestamped('%s TCP SSL error %s' % (self.connectionID, e.strerror))
                        oSSLConnection.shutdown(socket.SHUT_RDWR)
                        oSSLConnection.close()
                        oSSLConnection = None
                self.connection = oSSLConnection
            elif self.dListener.get(THP_SSH, None) != None:
                if ModuleLoaded('paramiko'):
                    if THP_KEYFILE in self.dListener[THP_SSH]:
                        ExportFile(self.dListener[THP_SSH][THP_KEYFILE])
                        oRSAKey = paramiko.RSAKey(filename=self.dListener[THP_SSH][THP_KEYFILE])
                    else:
                        oRSAKey = paramiko.RSAKey.generate(1024)
                        self.oOutput.LineTimestamped('%s TCP SSH generated RSA key' % self.connectionID)
                    oTransport = paramiko.Transport(oSocketConnection)
                    if THP_BANNER in self.dListener[THP_SSH]:
                        oTransport.local_version = self.dListener[THP_SSH][THP_BANNER]
                    oTransport.load_server_moduli()
                    oTransport.add_server_key(oRSAKey)
                    oSSHServer = cSSHServer(self.oOutput, self.connectionID)
                    try:
                        oTransport.start_server(server=oSSHServer)
                    except paramiko.SSHException:
                        self.oOutput.LineTimestamped('%s TCP SSH negotiation failed' % self.connectionID)
                        raise
                    self.oOutput.LineTimestamped('%s TCP SSH banner %s' % (self.connectionID, oTransport.remote_version))
                    oSSHConnection = oTransport.accept(20)
                    if oSSHConnection is None:
                        self.oOutput.LineTimestamped('%s TCP SSH no channel' % self.connectionID)
                        raise Exception('TCP SSH no channel')
                    self.oOutput.LineTimestamped('%s TCP SSH authenticated' % self.connectionID)
                    oSSHServer.oEvent.wait(10)
                    if not oSSHServer.oEvent.is_set():
                        self.oOutput.LineTimestamped('%s TCP SSH no shell' % self.connectionID)
                        raise Exception('TCP SSH no shell')
                    self.connection = oSSHConnection
                    oSSHFile = oSSHConnection.makefile('rU')
                else:
                    self.oOutput.LineTimestamped('%s TCP can not create SSH server, Python module paramiko missing' % self.connectionID)
                    self.connection = oSocketConnection
            else:
                self.connection = oSocketConnection
            if self.connection == None:
                return
            if THP_ECHO in self.dListener and inspect.isclass(self.dListener[THP_ECHO]):
                echoObject = self.dListener[THP_ECHO](self.oOutput)
            else:
                echoObject = None
            if THP_BANNER in self.dListener:
                self.SendTCP(ReplaceAliases(self.dListener[THP_BANNER]))
                self.oOutput.LineTimestamped('%s TCP send banner' % self.connectionID)
            stopConnection = False
            for i in range(0, self.dListener.get(THP_LOOP, 1)):
                if oSSHFile == None:
                    data = self.connection.recv(self.options.readbuffer)
                    if THP_READALL in self.dListener:
                        self.connection.setblocking(0)
                        if self.dListener[THP_READALL] == True:
                            sleepextra = 0
                        else:
                            sleepextra = self.dListener[THP_READALL]
                        while True:
                            try:
                                time.sleep(sleepextra)
                                dataextra = self.connection.recv(self.options.readbuffer)
                            except BlockingIOError:
                                self.connection.setblocking(1)
                                break
                            data += dataextra
                else:
                    data = oSSHFile.readline()
                self.LogData('TCP', 'data', data)
                if THP_MINIMUM_DATA_LENGTH in self.dListener:
                    previous += data
                    if len(previous) < self.dListener[THP_MINIMUM_DATA_LENGTH]:
                        self.oOutput.LineTimestamped('%s TCP data too short' % self.connectionID)
                        continue
                    data = previous
                    previous = b''
                    self.LogData('TCP', 'joined data', data)
                for splitdata in SplitIfRequested(self.dListener, data):
                    if splitdata != data:
                        self.LogData('TCP', 'splitdata', splitdata)
                    if THP_ECHO in self.dListener:
                        if echoObject != None:
                            echodata = echoObject.Process(splitdata)
                        elif callable(self.dListener[THP_ECHO]):
                            echodata = self.dListener[THP_ECHO](splitdata)
                        else:
                            echodata = splitdata
                        if echodata != None:
                            self.SendTCP(echodata)
                            self.LogData('TCP', 'send echo', echodata)
                    if THP_REPLY in self.dListener:
                        self.SendTCP(ReplaceAliases(self.dListener[THP_REPLY], self.EchoThis(splitdata)), 'TCP send reply')
                    if THP_MATCH in self.dListener:
                        dKeys = {}
                        for item in self.dListener[THP_MATCH].items():
                            for key in item[1].keys():
                                dKeys[key] = 1 + dKeys.get(key, 0)
                        if THP_REGEX in dKeys and THP_STARTSWITH in dKeys:
                            self.oOutput.LineTimestamped('THP_MATCH cannot contain both THP_REGEX and THP_STARTSWITH!')
                        elif THP_REGEX in dKeys:
                            matches = []
                            for matchname, dMatch in self.dListener[THP_MATCH].items():
                                if THP_REGEX in dMatch:
                                    oMatch = re.search(dMatch[THP_REGEX], splitdata, re.DOTALL)
                                    if oMatch != None:
                                        matches.append([len(oMatch.group()), dMatch, matchname])
                            dataToSend, messagesToLog, stopConnection = self.ProcessMatches(matches, splitdata)
                            if dataToSend != None:
                                self.SendTCP(dataToSend)
                            for message in messagesToLog:
                                self.oOutput.LineTimestamped(message)
                            if stopConnection:
                                break
                        elif THP_STARTSWITH in dKeys:
                            matches = []
                            for matchname, dMatch in self.dListener[THP_MATCH].items():
                                if THP_STARTSWITH in dMatch and splitdata.startswith(dMatch[THP_STARTSWITH]):
                                    matches.append([len(dMatch[THP_STARTSWITH]), dMatch, matchname])
                            dataToSend, messagesToLog, stopConnection = self.ProcessMatches(matches, splitdata)
                            if dataToSend != None:
                                self.SendTCP(dataToSend)
                            for message in messagesToLog:
                                self.oOutput.LineTimestamped(message)
                            if stopConnection:
                                break
                if stopConnection:
                    break
            #a# is it necessary to close both oSSLConnection and oSocketConnection?
            if oSSLConnection != None:
                oSSLConnection.shutdown(socket.SHUT_RDWR)
                oSSLConnection.close()
            if sys.version_info[0] == 2:
                oSocketConnection.shutdown(socket.SHUT_RDWR)
                oSocketConnection.close()
            self.oOutput.LineTimestamped('%s TCP closed' % self.connectionID)
        except socket.timeout:
            self.oOutput.LineTimestamped('%s TCP timeout' % self.connectionID)
        except Exception as e:
            if hasattr(e, '__traceback__') and hasattr(e.__traceback__, 'tb_lineno'):
                lineno = ' line %d' % e.__traceback__.tb_lineno
            else:
                lineno = ''
            self.oOutput.LineTimestamped("%s TCP exception%s '%s'" % (self.connectionID, lineno, str(e)))

    def SendTCP(self, data, logmessage=''):
        if THP_DELAY in self.dListener:
            time.sleep(self.dListener[THP_DELAY])
        self.connection.send(data)
        if logmessage != '':
            self.oOutput.LineTimestamped('%s %s len=%d md5=%s' % (self.connectionID, logmessage, len(data), hashlib.md5(data).hexdigest()))
            httpcontent = GetContent(data)
            if httpcontent != '':
                self.oOutput.LineTimestamped('%s (%s) HTTP content len=%d md5=%s' % (self.connectionID, logmessage, len(httpcontent), hashlib.md5(httpcontent).hexdigest()))
        if self.options.dumpdata:
            self.LogData('TCP', 'sent', data)

    def ProcessMatches(self, matches, datain):
        result = False
        data = None
        logs = []
        if matches == []:
            for matchname, dMatch in self.dListener[THP_MATCH].items():
                if THP_ELSE in dMatch:
                    matches.append([0, dMatch, THP_ELSE])
        if matches != []:
            matches = sorted(matches, reverse=True)
            longestmatches = [match for match in matches if match[0] == matches[0][0]]
            longestmatch = random.choice(longestmatches)
            dMatchLongest = longestmatch[1]
            if THP_REPLY in dMatchLongest:
                data = ReplaceAliases(dMatchLongest[THP_REPLY], self.EchoThis(datain))
                logs.append('%s %s send %s reply' % (self.connectionID, self.protocol, longestmatch[2]))
            if dMatchLongest.get(THP_ACTION, b'') == THP_DISCONNECT:
                logs.append('%s %s disconnecting' % (self.connectionID, self.protocol))
                result = True
        return data, logs, result

    def RunUDP(self):
        self.protocol = THP_UDP
        data, address = self.oSocket.recvfrom(self.options.readbuffer)
        self.connectionID = '%s:%d-%s:%d' % (address + self.oSocket.getsockname())
        self.oOutput.LineTimestamped('%s UDP connection' % self.connectionID)
        self.LogData('UDP', 'data', data)
        self.dListener, dummy = GetListener(self.oSocket.getsockname()[1], self.protocol)
        if self.CheckAllowList():
            if self.CheckAllowList(address[0]):
                self.oOutput.LineTimestamped('%s %s %s on allowlist' % (self.connectionID, self.protocol, address[0]))
            else:
                self.oOutput.LineTimestamped('%s %s %s not on allowlist' % (self.connectionID, self.protocol, address[0]))
                return

        if THP_ECHO in self.dListener and inspect.isclass(self.dListener[THP_ECHO]):
            echoObject = self.dListener[THP_ECHO](self.oOutput)
        else:
            echoObject = None
        for splitdata in SplitIfRequested(self.dListener, data):
            if splitdata != data:
                self.LogData('UDP', 'splitdata', splitdata)
            if THP_ECHO in self.dListener:
                if echoObject != None:
                    echodata = echoObject.Process(splitdata)
                elif callable(self.dListener[THP_ECHO]):
                    echodata = self.dListener[THP_ECHO](splitdata)
                else:
                    echodata = splitdata
                if echodata != None:
                    self.SendUDP(echodata, address)
                    self.LogData('UDP', 'send echo', echodata)
            if THP_REPLY in self.dListener:
                self.SendUDP(ReplaceAliases(self.dListener[THP_REPLY], self.EchoThis(splitdata)), address)
                self.oOutput.LineTimestamped('%s UDP send reply' % self.connectionID)
            if THP_MATCH in self.dListener:
                dKeys = {}
                for item in self.dListener[THP_MATCH].items():
                    for key in item[1].keys():
                        dKeys[key] = 1 + dKeys.get(key, 0)
                if THP_REGEX in dKeys and THP_STARTSWITH in dKeys:
                    self.oOutput.LineTimestamped('THP_MATCH cannot contain both THP_REGEX and THP_STARTSWITH!')
                elif THP_REGEX in dKeys:
                    matches = []
                    for matchname, dMatch in self.dListener[THP_MATCH].items():
                        if THP_REGEX in dMatch:
                            oMatch = re.search(dMatch[THP_REGEX], splitdata, re.DOTALL)
                            if oMatch != None:
                                matches.append([len(oMatch.group()), dMatch, matchname])
                    dataToSend, messagesToLog, stopConnection = self.ProcessMatches(matches, splitdata)
                    if dataToSend != None:
                        self.SendUDP(dataToSend, address)
                    for message in messagesToLog:
                        self.oOutput.LineTimestamped(message)
                    if stopConnection:
                        break
                elif THP_STARTSWITH in dKeys:
                    matches = []
                    for matchname, dMatch in self.dListener[THP_MATCH].items():
                        if THP_STARTSWITH in dMatch and splitdata.startswith(dMatch[THP_STARTSWITH]):
                            matches.append([len(dMatch[THP_STARTSWITH]), dMatch, matchname])
                    dataToSend, messagesToLog, stopConnection = self.ProcessMatches(matches, splitdata)
                    if dataToSend != None:
                        self.SendUDP(dataToSend, address)
                    for message in messagesToLog:
                        self.oOutput.LineTimestamped(message)
                    if stopConnection:
                        break

    def SendUDP(self, data, address):
        if THP_DELAY in self.dListener:
            time.sleep(self.dListener[THP_DELAY])
        self.oSocket.sendto(data, address)
        if self.options.dumpdata:
            self.LogData('UDP', 'sent', data)

    def LogData(self, protocol, name, data):
        if self.options.format == 'repr':
            self.oOutput.LineTimestamped('%s %s %s %s' % (self.connectionID, protocol, name, repr(data)))
        else:
            self.oOutput.LineTimestamped('%s %s %s' % (self.connectionID, protocol, name))
            if self.options.format == 'a':
                self.oOutput.Line(HexAsciiDump(data))
            elif self.options.format == 'A':
                self.oOutput.Line(HexAsciiDump(data, True))
            elif self.options.format == 'x':
                self.oOutput.Line(HexDump(data))
            elif self.options.format == 'X':
                self.oOutput.Line(binascii.b2a_hex(data))
            elif self.options.format == 'b':
                self.oOutput.Line(Base64Dump(data))
            elif self.options.format == 'B':
                self.oOutput.Line(Base64Dump(data, True))
            elif self.options.format == 'p':
                self.oOutput.Line(data.decode())

def ParseErrorMessage(error):
    oMatch = re.search(r'\[(WinError|Errno) ([0-9]+)\]', error)
    if oMatch != None:
        return int(oMatch.groups()[1])
    else:
        return 0

def AddPorts(dListeners, ports):
    for port_protocol, port_number, port_reference in ports:
        if not port_number in dListeners:
            dListeners[port_number] = {}
        config = {}
        if port_reference != None:
            config = {THP_REFERENCE: port_reference}
        dListeners[port_number][port_protocol] = config

def StartsWithGetRemainder(strIn, strStart):
    if strIn.startswith(strStart):
        return True, strIn[len(strStart):]
    else:
        return False, None

def ParseArgumentListeners(argument):
    global dListeners
    global dVariables

    for key, value in globals().items():
        if isinstance(value, str) and key.startswith('THP_'):
            argument = argument.replace(key, repr(value))

    result, remainder = StartsWithGetRemainder(argument, '#v#') # v = variable
    if result:
        key, value = remainder.split('=', 1)
        dVariables[key] = value
        return

    result, remainder = StartsWithGetRemainder(argument, '#a#') # a = additional
    if result:
        for key, value in ast.literal_eval(remainder).items():
            dListeners[key] = value
        return

    result, remainder = StartsWithGetRemainder(argument, '#m#') # m = main
    if not result:
        result, remainder = StartsWithGetRemainder(argument, '#')
    if result:
        dListeners = ast.literal_eval(remainder)
        return

    raise Exception('Unexpected argument: %s' % argument)

def CreateZipFileObject(arg1, arg2):
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

def ReadBinaryFile(filename):
    oOutput.LineTimestamped('Reading binary file: %s' % filename)

    if filename == '':
        return b''

    isZIP, zipfilename = StartsWithGetRemainder(filename, '#z#') # z = zip

    if isZIP:
        try:
            oZipfile = CreateZipFileObject(zipfilename, 'r')
            data = oZipfile.open(oZipfile.infolist()[0], 'r', b'infected').read()
            oOutput.LineTimestamped('File %s inside ZIP %s read: size %d MD5 %s' % (oZipfile.infolist()[0].filename, zipfilename, len(data), hashlib.md5(data).hexdigest()))
            return data
        except Exception as e:
            oOutput.LineTimestamped('Error reading file %s: %s' % (filename, e))
            raise e
    else:
        try:
            with open(filename, 'rb') as fIn:
                data = fIn.read()
            oOutput.LineTimestamped('File %s read: size %d MD5 %s' % (filename, len(data), hashlib.md5(data).hexdigest()))
            return data
        except Exception as e:
            oOutput.LineTimestamped('Error reading file %s: %s' % (filename, e))
            raise e

def SimpleListener(arguments, options):
    global dListeners
    global oOutput
    global dVariables
    global epochOffset

    rootname = os.path.splitext(os.path.basename(sys.argv[0]))[0]

    oOutput = cOutput('%s_%s.log' % (rootname, FormatTime()), True)

    oOutput.LineTimestamped('Arguments: %s' % repr(sys.argv))

    if options.utcdatetime != '':
        epochOffset = -(time.time() - calendar.timegm(time.strptime(options.utcdatetime, '%Y-%m-%dT%H:%M:%S')))
    else:
        epochOffset = 0
    oOutput.LineTimestamped('Epoch offset: %d' % epochOffset)

    dVariables = {}
    for argument in arguments:
        if argument.startswith('#'):
            ParseArgumentListeners(argument)
            if len(dVariables) > 0:
                oOutput.LineTimestamped('Variables:')
                for item in dVariables.items():
                    oOutput.LineTimestamped(' %s=%s' % item)

        else:
            oOutput.LineTimestamped('Exec: %s' % argument)
            exec(open(argument, 'r').read(), globals(), globals())

    templates = []
    for template in dListeners.keys():
        if isinstance(template, str) and template != THP_DATA:
            templates.append(template)
    if templates != []:
        oOutput.LineTimestamped('Templates:')
        for template in templates:
            oOutput.LineTimestamped(' %s' % template)

    if options.ports != '':
        oOutput.LineTimestamped('Ports specified via command-line option: %s' % options.ports)
        dListeners = {key: value for key, value in dListeners.items() if not isinstance(key, int)}
        AddPorts(dListeners, ParsePorts(options.ports))

    if options.extraports != '':
        oOutput.LineTimestamped('Extra ports: %s' % options.extraports)
        AddPorts(dListeners, ParsePorts(options.extraports))

    sockets = []

    sshLogToFile = False
    for port in dListeners.keys():
        dListener, reference = GetListener(port, THP_TCP)
        if dListener == None:
            continue

        if THP_SSL in dListener:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                ExportFile(dListener[THP_SSL][THP_CERTFILE])
                ExportFile(dListener[THP_SSL][THP_KEYFILE])
                context.load_cert_chain(certfile=dListener[THP_SSL][THP_CERTFILE], keyfile=dListener[THP_SSL][THP_KEYFILE])
                dListener[THP_SSLCONTEXT] = context
                oOutput.LineTimestamped('Created SSL context for %d' % port)
            except IOError as e:
                if '[Errno 2]' in str(e):
                    oOutput.LineTimestamped('Error reading certificate and/or key file: %s %s' % (dListener[THP_SSL][THP_CERTFILE], dListener[THP_SSL][THP_KEYFILE]))
                else:
                      oOutput.LineTimestamped('Error creating SSL context: %s' % e)
                oOutput.LineTimestamped('SSL not enabled for %d' % port)

        if THP_SSH in dListener and not sshLogToFile:
            if ModuleLoaded('paramiko'):
                paramiko.util.log_to_file('%s_ssh_%s.log' % (rootname, FormatTime()))
                sshLogToFile = False

        oSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        oSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            oSocket.bind((options.address, port))
        except socket.error as e:
            errornumber = ParseErrorMessage(str(e))
            if errornumber == 98: #[Errno 98] Address already in use
                oOutput.LineTimestamped('Port %d can not be used, it is already open' % port)
                continue
            elif errornumber == 99 or errornumber == 10049: #[Errno 99] Cannot assign requested address [Errno 10049] The requested address is not valid in its context
                oOutput.LineTimestamped('Address %s can not be used (port %d)' % (options.address, port))
                continue
            elif errornumber == 10013: #[Errno 10013] An attempt was made to access a socket in a way forbidden by its access permissions
                oOutput.LineTimestamped('Port %d can not be used, access is forbidden' % port)
                continue
            else:
                raise e
        try:
            oSocket.listen(5)
        except socket.error as e:
            errornumber = ParseErrorMessage(str(e))
            if errornumber == 98: #[Errno 98] Address already in use
                oOutput.LineTimestamped('Port %d can not be used, it is already open' % port)
                continue
            elif errornumber == 99 or errornumber == 10049: #[Errno 99] Cannot assign requested address [Errno 10049] The requested address is not valid in its context
                oOutput.LineTimestamped('Address %s can not be used (port %d)' % (options.address, port))
                continue
            elif errornumber == 10013: #[Errno 10013] An attempt was made to access a socket in a way forbidden by its access permissions
                oOutput.LineTimestamped('Port %d can not be used, access is forbidden' % port)
                continue
            else:
                raise e
        oOutput.LineTimestamped('Listening on %s TCP %d%s' % (oSocket.getsockname() + (PrefixIfNeeded(reference), )))
        sockets.append(oSocket)

    for port in dListeners.keys():
        dListener, reference = GetListener(port, THP_UDP)
        if dListener == None:
            continue

        oSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        oSocket.bind((options.address, port))
        oOutput.LineTimestamped('Listening on %s UDP %d%s' % (oSocket.getsockname() + (PrefixIfNeeded(reference) , )))
        sockets.append(oSocket)

    if sockets == []:
        return

    if options.loglevel == 2:
        oOutput.bothoutputs = False

    if options.validate:
        return

    while True:
        readables, writables, exceptionals = select.select(sockets, [], [])
        for oSocket in readables:
            try:
                cConnectionThread(oSocket, oOutput, options).start()
            except:
                oOutput.Exception()
        if options.prompt:
            time.sleep(1)
            oOutput.LineTimestamped('Prompting to stop')
            answer = input('Answer s to stop, any other answer to continue: ')
            if answer == 's':
                oOutput.LineTimestamped('Stopping')
                return

def Main():
    moredesc = '''

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-t', '--timeout', type=int, default=10, help='Timeout value for sockets in seconds (default 10s)')
    oParser.add_option('-r', '--readbuffer', type=int, default=10240, help='Size read buffer in bytes (default 10240)')
    oParser.add_option('-a', '--address', default='0.0.0.0', help='Address to listen on (default 0.0.0.0)')
    oParser.add_option('-P', '--ports', default='', help='Ports to listen on (overrides ports configured in the program)')
    oParser.add_option('-p', '--extraports', default='', help='Extra ports to listen on (default none)')
    oParser.add_option('-f', '--format', default='repr', help='Output format (default repr)')
    oParser.add_option('-d', '--dumpdata', action='store_true', default=False, help='Dump sent data')
    oParser.add_option('--loglevel', type=int, default=1, help='Log level: 1=log everything to console and log file, 2=log only startup to console, log everything to file')
    oParser.add_option('--validate', action='store_true', default=False, help='Stop the program before processing connections')
    oParser.add_option('--utcdatetime', default='', help='The UTC start date & time to be used for time variables (format: 2022-07-07T09:48:00)')
    oParser.add_option('--prompt', action='store_true', default=False, help='Prompt after each processed connection')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    SimpleListener(args, options)

if __name__ == '__main__':
    Main()
