#!/usr/bin/python
# V1.1 15/01/2007 - 10/07/2007
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk
#
# History:
#  10/07/2007: Handle comments inside script tags


import sgmllib
import sys

class MyParser(sgmllib.SGMLParser):
    "A simple parser class."

    def parse(self, s):
        "Parse the given string 's'."
        self.feed(s)
        self.close()

    def __init__(self, verbose=0):
        "Initialise an object, passing 'verbose' to the superclass."

        sgmllib.SGMLParser.__init__(self, verbose)
        self.hyperlinks = []
        self.inSCRIPT = 0
        self.SCRIPTdata = ""
        self.countScripts = 0
        self.scriptingLanguage = ""

    def start_script(self, attributes):
        "Process a <script> tag."

        self.scriptingLanguage = ""
        for name, value in attributes:
            if name == "language":
                self.scriptingLanguage = value
        self.inSCRIPT = 1
        self.SCRIPTdata = ""
        self.countScripts += 1

    def end_script(self):
        "Process a </script> tag."

        self.inSCRIPT = 0
        fScript = open("script.%d.%s" % (self.countScripts, self.scriptingLanguage), "w")
        fScript.write(self.SCRIPTdata)
        fScript.close()

    def handle_data(self, s):
        "Process data between <script> tags"

        if self.inSCRIPT == 1:
            self.SCRIPTdata = self.SCRIPTdata + s

    def handle_comment(self, s):
        "Process data between comment tags"

        if self.inSCRIPT == 1:
            self.SCRIPTdata = self.SCRIPTdata + s

    def get_SCRIPTdata(self):
        "Return the text between <script> tags."

        return self.SCRIPTdata

if len(sys.argv) != 2:
    print "Usage: extractscripts html-file"
else:
    fHTML = open(sys.argv[1], "r")
    s = fHTML.read()
    fHTML.close()
    del fHTML

    myparser = MyParser()
    myparser.parse(s)
