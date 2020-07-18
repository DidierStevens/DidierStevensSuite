#!/usr/bin/env python

__description__ = 'VBA project stream plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2020/07/17'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2020/07/16: start
  2020/07/17: added Hashcat hash

Todo:
"""

def Decrypt(data):
    if sys.version_info[0] == 2:
        data = [ord(char) for char in data]
    seed = data[0]
    version = data[1] ^ seed
    projectkey = data[2] ^ seed
    ignore = int((seed & 6) / 2)
    
    result = ['seed: 0x%02x' % seed, 'version: 0x%02x' % version, 'projectkey: 0x%02x' % projectkey, 'ignore: %d' % ignore]

    pb = projectkey
    decoded = []
    for iter in range(3, len(data)):
        byte = ((data[iter - 2] + pb) ^ data[iter]) % 0x100
        if ignore == 0:
            decoded.append(byte)
        else:
           ignore -= 1
        pb = byte

    return result, decoded

def IntegersToHex(integers):
    return ''.join(['%02x' % integer for integer in integers])

# A plugin defines a class that is instantiated for each stream in the OLE document.
# This class inherits from class cPluginParent.
# The name of the class (cVBAProject in this example) can be chosen freely.
# But avoid name conflicts with other plugins.
class cVBAProject(cPluginParent):

    # Set class variable macroOnly to True if the plugins requires VBA macro text (decompressed stream),
    # or to False if the plugin requires the raw stream content.
    # This class variable is defined and set to False in the parent class cPluginParent.
    macroOnly = False

    # Class variable name contains the name of the plugin to be displayed in oledump's output.
    name = 'VBA project plugin'

    # Method __init__ provides data via 3 arguments:
    #  name is the name of the stream as returned by olefile's listdir method.
    #  stream is the content of the stream as returned by olefile's read method.
    #   stream is None is no stream is present (container)
    #   if class variable macroOnly is True, then stream contains the VBA macro code as one long string (e.g. the decompressed stream)
    #  options is a string passed to --pluginoptions.
    def __init__(self, name, stream, options):
        # Storing the arguments for later use by Analyze method
        self.streamname = name
        self.stream = stream
        self.options = options

        # Object property ran must be set to False before the plugin runs.
        # oledump only displays output for the plugin if property ran is True.
        self.ran = False

    # Method Analyze is called by oledump to let the plugin analyze the stream.
    # This method must return a list of strings: this is the plugin output to be displayed by oledump.
    # This method must also set object property ran to True to have oledump display output for this plugin.
    def Analyze(self):

        # This example counts the numbers of bytes with value FF in the stream,
        # and produces one line of output if the count is more than 0.
        
        result = []

        if self.streamname[-1] != 'PROJECT':
            return result
            
        oMatch = re.search(b'DPB="([A-F0-9]+)"', self.stream, re.I)
        if oMatch == None:
            return result
            
        encoded = binascii.a2b_hex(oMatch.groups()[0])
        result, decoded = Decrypt(encoded)

        if decoded[0:4] == [29, 0, 0, 0]:
            data = []
            for index, value in enumerate(bin(decoded[5] * 0x10000 + decoded[6] * 0x100 + decoded[7])[2:]):
                data.append(decoded[8 + index] if value == '1' else 0x00)
            result.append('VBA project is password protected')
#            result.append(' JtR hash: vbapassword:$dynamic_24$%s$HEX$%s' % (IntegersToHex(decoded[12:32]), IntegersToHex(decoded[8:12])))
            result.append(' JtR hash: vbapassword:$dynamic_24$%s$HEX$%s' % (IntegersToHex(data[4:24]), IntegersToHex(data[0:4])))
            result.append(' Hashcat hash (-m 110 --hex-salt): %s:%s' % (IntegersToHex(data[4:24]), IntegersToHex(data[0:4])))
        elif decoded == [1, 0, 0, 0, 0]:
            result.append('VBA project is not password protected')
        else:
            result.append('Unexpected data: ' + repr(decoded))

        self.ran = True

        return result

# The plugin class must be registered with oledump by calling function AddPlugin with
# the name of the plugin class (cVBAProject in this example).
AddPlugin(cVBAProject)

# The plugin code is not restricted or sandboxed. Plugin code runs with the same privileges and accesses as oledump.
# The plugin code and interface is not validated before execution.
# There is no object persistence across streams. If you need this, get in touch.
