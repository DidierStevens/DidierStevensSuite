#!/usr/bin/env python

__description__ = 'Stream sample plugin for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2016/09/05'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/09/05: start

Todo:
"""

# A plugin defines a class that is instantiated for each stream in the OLE document.
# This class inherits from class cPluginParent.
# The name of the class (cStreamSample in this example) can be chosen freely.
# But avoid name conflicts with other plugins.
class cStreamSample(cPluginParent):

    # Set class variable macroOnly to True if the plugins requires VBA macro text (decompressed stream),
    # or to False if the plugin requires the raw stream content.
    # This class variable is defined and set to False in the parent class cPluginParent.
    macroOnly = False

    # Class variable name contains the name of the plugin to be displayed in oledump's output.
    name = 'Stream sample plugin'

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
        ffs = [b for b in self.stream if b == '\xff']
        if len(ffs) > 0:
            result.append('Number of 0xFF bytes in stream: %d' % len(ffs))

        self.ran = True

        return result

# The plugin class must be registered with oledump by calling function AddPlugin with
# the name of the plugin class (cStreamSample in this example).
AddPlugin(cStreamSample)

# The plugin code is not restricted or sandboxed. Plugin code runs with the same privileges and accesses as oledump.
# The plugin code and interface is not validated before execution.
# There is no object persistence across streams. If you need this, get in touch.
