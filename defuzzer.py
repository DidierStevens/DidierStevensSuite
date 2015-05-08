#!/usr/bin/env python

__description__ = 'Merge 3 or more fuzzed files back to original'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2013/03/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2013/03/12: start
  2013/03/14: generalized to more than 3 files
  2013/04/05: added fuzz bytes statistics

Todo:
"""

import optparse
import glob

def MostPrevalent(dChars):
    maximumChar = None
    maximumValue = 0
    maximumCount = 0
    for key, value in dChars.items():
        if value > maximumValue:
            maximumValue = value
            maximumCount = 1
            maximumChar = key
        elif value == maximumValue:
            maximumCount += 1
    if maximumCount == 1:
        return maximumChar
    else:
        return None

def DicAddGeneric(dicA, dicB):
    for key, value in dicB.items():
        if key in dicA:
            dicA[key] += value
        else:
            dicA[key] = value

def DeFuzzer(filenameOut, filenames):
    countDifference = 0
    countLengthSequence = 0
    countSequences = 0
    maxLengthSequence = 0
    minLengthSequence = 0
    dFiles = {}
    dFuzzBytes = {}
    for filename in filenames:
        dFiles[filename] = open(filename, 'rb')
    fOut = open(filenameOut, 'wb')
    while True:
        dChars = {}
        for dFile in dFiles.values():
            c = dFile.read(1)
            if not c in dChars:
                dChars[c] = 0
            dChars[c] += 1
        if '' in dChars: # we reached the end of at least one file
            if countLengthSequence > 0:
                countSequences += 1
                maxLengthSequence = max(countLengthSequence, maxLengthSequence)
                if minLengthSequence == 0:
                    minLengthSequence = countLengthSequence
                else:
                    minLengthSequence = min(countLengthSequence, minLengthSequence)
                countLengthSequence = 0
            break
        if len(dChars) == 1: # all characters identical
            fOut.write(dChars.keys()[0])
            if countLengthSequence > 0:
                countSequences += 1
                maxLengthSequence = max(countLengthSequence, maxLengthSequence)
                if minLengthSequence == 0:
                    minLengthSequence = countLengthSequence
                else:
                    minLengthSequence = min(countLengthSequence, minLengthSequence)
                countLengthSequence = 0
        else:
            result = MostPrevalent(dChars)
            if result == None:
                print('Unable to defuzz, all bytes are different')
                break
            else:
                fOut.write(result)
                countDifference += 1
                countLengthSequence += 1
                del dChars[result]
                DicAddGeneric(dFuzzBytes, dict([(key, 1) for key, value in dChars.items()]))
    for dFile in dFiles.values():
        dFile.close()
    fOut.close()
    print('Number of defuzzed bytes: %d' % countDifference)
    print('Number of defuzzed sequences: %d' % countSequences)
    print('Length of shortest defuzzed sequence: %d' % minLengthSequence)
    print('Length of longest defuzzed sequence: %d' % maxLengthSequence)
    keys = dFuzzBytes.keys()
    keys.sort()
    print('Fuzz bytes:')
    print(', '.join(['%s: %d' % (repr(key), dFuzzBytes[key]) for key in keys]))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] mergedfile file-in-1 file-in-2 file-in-3 ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-o', '--option', action='store_true', default=False, help='option')
    (options, args) = oParser.parse_args()

    files = sum(map(glob.glob, args[1:]), [])
    if len(files) < 3:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        DeFuzzer(args[0], files)

if __name__ == '__main__':
    Main()
