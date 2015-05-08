#!/usr/bin/env python

#2014/09/30

class cPDFiDTriage(cPluginParent):
#    onlyValidPDF = True
    name = 'Triage plugin'

    def __init__(self, oPDFiD):
        self.oPDFiD = oPDFiD

    def Score(self):
        for keyword in ('/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFile', '/XFA', '/Colors > 2^24'):
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                return 1.0
        if self.oPDFiD.keywords['obj'].count != self.oPDFiD.keywords['endobj'].count:
            return 1.0
        if self.oPDFiD.keywords['stream'].count != self.oPDFiD.keywords['endstream'].count:
            return 1.0
        return 0.0

AddPlugin(cPDFiDTriage)
