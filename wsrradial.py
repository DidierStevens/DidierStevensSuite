#!/usr/bin/python
"""V0.1 2008/08/24

Tool for radial plotting of wi-spy wsr files

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

requires Construct http://construct.wikispaces.com/
requires Python Imaging Library http://www.pythonware.com/products/pil/

History:
 2008/08/24: start
 2008/08/25: hue color map

Todo:
 - 
"""

from construct import *
import time
from optparse import OptionParser
import Image,ImageDraw

iImageSize = 1000

def Timestamp2String(iSeconds, iMicroseconds):
    return '%s,%06d' % (('%d/%02d/%02d %02d:%02d:%02d' % time.gmtime(iSeconds)[0:6]), iMicroseconds)

def RSSI2Amplitude(iRawRSSI, fAmplitudeOffset, fAmplitudeResolution):
    return (iRawRSSI * fAmplitudeResolution + fAmplitudeOffset) / 1000.0

def RawRSSI2Color(iRawRSSI, iRawRSSIMin, iRawRSSIMax):
    dPercentage = 1.0 - ((iRawRSSI - iRawRSSIMin) * 1.0) / ((iRawRSSIMax - iRawRSSIMin) * 1.0)
    return 'hsl(%d,100%%,50%%)' % int(dPercentage * 259)
    
def PlotSegment(oDraw, iDirection, iDirections, aRawRSSIAverage, iRawRSSIMin, iRawRSSIMax):
    dAngleSegment = 360.0 / (iDirections * 1.0)
    dAngle = dAngleSegment * iDirection - 90.0
    for iIndex, iRawRSSI in enumerate(aRawRSSIAverage):
        strColor = RawRSSI2Color(iRawRSSI, iRawRSSIMin, iRawRSSIMax)
        oDraw.arc((iImageSize/2-iImageSize/2/10-iIndex, iImageSize/2-iImageSize/2/10-iIndex, iImageSize/2+iImageSize/2/10+iIndex, iImageSize/2+iImageSize/2/10+iIndex), int(dAngle - dAngleSegment / 2.0), int(dAngle + dAngleSegment / 2.0 + 1), strColor)

def PlotLegend(oDraw, iRawRSSIMin, iRawRSSIMax, oHeader):
    iWidth = 5
    iHeight = iWidth * 4
    strMin = '%.1f dBm' % RSSI2Amplitude(iRawRSSIMin, oHeader.amplitude_offset, oHeader.amplitude_resolution)
    iMinTextWidth = oDraw.textsize(strMin)[0]
    oDraw.text((0, iWidth/2), strMin, fill='#FFFFFF')
    for iRawRSSIIter in range(iRawRSSIMin, iRawRSSIMax+1):
        oDraw.rectangle([(iRawRSSIIter-iRawRSSIMin)*iWidth+iMinTextWidth+5, 0, (iRawRSSIIter-iRawRSSIMin)*iWidth+iWidth-1+iMinTextWidth+5, iHeight], fill=RawRSSI2Color(iRawRSSIIter, iRawRSSIMin, iRawRSSIMax))
    strMax = '%.1f dBm' % RSSI2Amplitude(iRawRSSIMax, oHeader.amplitude_offset, oHeader.amplitude_resolution)
    oDraw.text(((iRawRSSIMax-iRawRSSIMin+1)*iWidth+iMinTextWidth+10, iWidth/2), strMax, fill='#FFFFFF')

def PlotRadial(aaRawRSSI, iDirections, oHeader):
    iRawRSSIMin = iRawRSSIMax = aaRawRSSI[0][0]
    for iIndex in range(iDirections):
        iRawRSSIMin = min(min(aaRawRSSI[iIndex]), iRawRSSIMin)
        iRawRSSIMax = max(max(aaRawRSSI[iIndex]), iRawRSSIMax)
    oImg = Image.new('RGB', (iImageSize, iImageSize), '#000000')
    oDraw = ImageDraw.Draw(oImg)
    PlotLegend(oDraw, iRawRSSIMin, iRawRSSIMax, oHeader)
    for iIndex in range(iDirections):
        PlotSegment(oDraw, iIndex, iDirections, aaRawRSSI[iIndex], iRawRSSIMin, iRawRSSIMax)
    return oImg

def Main():
    """Tool for radial plotting wi-spy wsr files
    """

    oParser = OptionParser(usage='usage: %prog [options] wsr-file plot-file', version='%prog 0.1')
    oParser.add_option('-i', '--interval', type='int', default=60, help='interval duration in seconds (default 60s)')
    oParser.add_option('-d', '--directions', type='int', default=8, help='number of directions used (default 8)')
    (oOptions, aArguments) = oParser.parse_args()

    if len(aArguments) != 2:
        oParser.print_help()
        print ''
        print '  Tool for radial plotting of wi-spy wsr files'
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'

    else:

        cHeader = Struct('header', UBInt32('version_number'),
                                   UBInt16('device_version'),
                                   UBInt32('starting_frequency'),
                                   UBInt32('frequency_resolution'),
                                   UBInt16('readings_per_sweep'),
                                   SBInt32('amplitude_offset'),
                                   UBInt32('amplitude_resolution'),
                                   UBInt16('max_steps'),
                                   SBInt64('first_bookmark'))

        try:
            oStreamIn = open(aArguments[0], 'rb')
        except:
            print 'error reading file %s' % aArguments[0]
            return

        try:
            oHeader = cHeader.parse_stream(oStreamIn)
        except:
            print 'error reading file %s' % aArguments[0]
            return

        cDataPacket = Struct('data_packet', UBInt32('seconds'),
                                            UBInt32('microseconds'),
                                            StrictRepeater(oHeader.readings_per_sweep, Byte('raw_RSSI')))

        iSecondsFirstSample = None
        iCounterSamplesTotal = 0
        aaRawRSSISum = [[0 for j in range(oHeader.readings_per_sweep)] for iIndex in range(oOptions.directions)]
        aaRawRSSIMax = [[0 for j in range(oHeader.readings_per_sweep)] for iIndex in range(oOptions.directions)]
        aRawRSSICounters = [0 for iIndex in range(oOptions.directions)]
        while oStreamIn.tell() < oHeader.first_bookmark:
            oDataPacket = cDataPacket.parse_stream(oStreamIn)
            iCounterSamplesTotal += 1
            if iSecondsFirstSample == None:
                iSecondsFirstSample = oDataPacket.seconds
                iMicroSecondsFirstSample = oDataPacket.microseconds
            iSecondsLastSample = oDataPacket.seconds
            iMicroSecondsLastSample = oDataPacket.microseconds
            iTimeIndex = (iSecondsLastSample - iSecondsFirstSample) / oOptions.interval
            if iTimeIndex < oOptions.directions:
                aRawRSSICounters[iTimeIndex] += 1
                for iIndex, iRawRSSI in enumerate(oDataPacket.raw_RSSI):
                    aaRawRSSISum[iTimeIndex][iIndex] += iRawRSSI
                    aaRawRSSIMax[iTimeIndex][iIndex] = max(iRawRSSI, aaRawRSSIMax[iTimeIndex][iIndex])
        oStreamIn.close()

        print
        print 'First sample: %s' % Timestamp2String(iSecondsFirstSample, iMicroSecondsFirstSample)
        print 'Last sample:  %s' % Timestamp2String(iSecondsLastSample, iMicroSecondsLastSample)
        print 'Sample count: %d' % iCounterSamplesTotal
        print aRawRSSICounters

        for iIndex in range(oOptions.directions):
            aaRawRSSISum[iIndex] = [iRawRSSI / aRawRSSICounters[iIndex] for iRawRSSI in aaRawRSSISum[iIndex]]
            
        oImgAVG = PlotRadial(aaRawRSSISum, oOptions.directions, oHeader)
        oImgAVG.save(aArguments[1]+'-avg.png', 'PNG')

        oImgMAX = PlotRadial(aaRawRSSIMax, oOptions.directions, oHeader)
        oImgMAX.save(aArguments[1]+'-max.png', 'PNG')

if __name__ == '__main__':
    Main()
