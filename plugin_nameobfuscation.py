#!/usr/bin/env python

#2013/11/04
#2013/11/08

class cPDFiDNameObfuscation(cPluginParent):
#    onlyValidPDF = True
    name = 'Name Obfuscation plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD

    def Score(self):
        if sum([oCount.hexcode for oCount in self.oPDFiD.keywords.values()]) > 0:
            return 1.0
        else:
            return 0.0

AddPlugin(cPDFiDNameObfuscation)
