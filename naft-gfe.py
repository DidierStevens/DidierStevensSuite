#!/usr/bin/env python

__description__ = 'Network Appliance Forensic Toolkit - Generic Frame Extraction'
__author__ = 'Didier Stevens'
__version__ = '0.0.7'
__date__ = '2013/10/12'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/11/20: start
  2011/11/22: added glob, duplicates removal, simple 802.1Q handling
  2011/11/30: ARP frames, refactoring to pfef module
  2012/01/26: NAFT refactoring
  2012/02/17: refactoring
  2012/02/20: V0.0.5: refactoring
  2012/02/23: added OUI.TXT filtering
  2013/10/12: V0.0.7: added buffer, buffersize, bufferoverlapsize options

Todo:
  other types of packets
  ethernet frames with other payload than ipv4
  handle MemoryError
  look at sequence numbers to sort packets
  look at IP addresses and MAC addresses to discover more evidence
  +- generate ad-hoc 010 template for analyzed file
  +- take 802.1Q tag into account for Ethernet frame: http://en.wikipedia.org/wiki/802.1Q
  + remove duplicates
  + set microtime to address in dump
"""

import optparse
import glob
import struct
import naft_uf
import naft_pfef
import time

def ExtractIPPacketsFromFile(filenamePCAP, filenamesRawData, options):
    naft_uf.LogLine('Start')
    if options.ouitxt == '':
        oFrames = naft_pfef.cFrames()
    else:
        oFrames = naft_pfef.cFrames(options.ouitxt)
    countProcessedFiles = 0

    for filenameRawData in filenamesRawData:
        if options.buffer:
            naft_uf.LogLine('Buffering file %s' % filenameRawData)
            oBufferFile = naft_uf.cBufferFile(filenameRawData, options.buffersize * 1024 * 1024, options.bufferoverlapsize * 1024 * 1024)
            while oBufferFile.Read():
                naft_uf.LogLine('Processing buffer 0x%x size %d MB %d%%' % (oBufferFile.index, len(oBufferFile.buffer) / 1024 / 1024, oBufferFile.Progress()))
                naft_uf.LogLine('Searching for IPv4 packets')
                naft_pfef.ExtractIPPackets(oFrames, oBufferFile.index, oBufferFile.buffer, options.options, options.duplicates, True, filenameRawData)
                naft_uf.LogLine('Searching for ARP Ethernet frames')
                naft_pfef.ExtractARPFrames(oFrames, oBufferFile.index, oBufferFile.buffer, options.duplicates, True, filenameRawData)
            if oBufferFile.error == MemoryError:
                naft_uf.LogLine('Data is too large to fit in memory, use smaller buffer')
            elif oBufferFile.error:
                naft_uf.LogLine('Error reading file')
            countProcessedFiles += 1
        else:
            naft_uf.LogLine('Reading file %s' % filenameRawData)
            rawData = naft_uf.File2Data(filenameRawData)
            if rawData == None:
                naft_uf.LogLine('Error reading file')
            if rawData == MemoryError:
                naft_uf.LogLine('File is too large to fit in memory')
            else:
                naft_uf.LogLine('Searching for IPv4 packets')
                naft_pfef.ExtractIPPackets(oFrames, 0, rawData, options.options, options.duplicates, True, filenameRawData)
                naft_uf.LogLine('Searching for ARP Ethernet frames')
                naft_pfef.ExtractARPFrames(oFrames, 0, rawData, options.duplicates, True, filenameRawData)
                countProcessedFiles += 1

    if countProcessedFiles > 0:
        naft_uf.LogLine('Writing PCAP file %s' % filenamePCAP)
        if not oFrames.WritePCAP(filenamePCAP):
            naft_uf.LogLine('Error writing PCAP file')

        naft_uf.LogLine('Number of identified frames:   %5d' % oFrames.countFrames)
        naft_uf.LogLine('Number of identified packets:  %5d' % oFrames.countPackets)
        naft_uf.LogLine('Number of frames in PCAP file: %5d' % len(oFrames.frames))

        if options.template:
            naft_uf.LogLine('Writing 010 template file %s' % options.template)
            if not oFrames.Write010Template(options.template):
                naft_uf.LogLine('Error writing 010 template file')

    naft_uf.LogLine('Done')

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] pcapfile dump ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--duplicates', action='store_true', default=False, help='include duplicates')
    oParser.add_option('-t', '--template', help='filename for the 010 Editor template to generate')
    oParser.add_option('-p', '--options', action='store_true', default=False, help='Search for IPv4 headers with options')
    oParser.add_option('-o', '--ouitxt', help='ouitxt filename to filter MAC addresses with unknown ID')
    oParser.add_option('-b', '--buffer', action='store_true', default=False, help='Buffer file in 100MB blocks with 1MB overlap')
    oParser.add_option('-S', '--buffersize', type='int', default=100, help='Size of buffer in MB (default 100MB)')
    oParser.add_option('-O', '--bufferoverlapsize', default=1, help='Size of buffer overlap in MB (default 1MB)')
    (options, args) = oParser.parse_args()

    if len(args) < 2:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    else:
        filenames = args[1:]
        filenames = sum(map(glob.glob, filenames), [])
        if options.template and len(filenames) > 1:
            print('Only one dump file allowed with option template')
            return
        ExtractIPPacketsFromFile(args[0], filenames, options)

if __name__ == '__main__':
    Main()
