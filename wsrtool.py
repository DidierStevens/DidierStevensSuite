#!/usr/bin/python
"""V0.2 2008/07/30

Tool for processing wi-spy wsr files

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

requires Construct http://construct.wikispaces.com/

History:
 2008/07/30: start
 2008/07/31: writing, filtering
 2008/08/02: V0.2 convert frequency to index, amplitude to RSSI for more performant filtering; added --reduce option (suggestion Ryan Woodings)

Todo:
 - time based filtering
"""

from construct import *
import time
from optparse import OptionParser

UNIT_MHZ = 'MHz'
UNIT_DBM = 'dBm'
PARAMETER_FREQUENCY = 'frequency'
PARAMETER_AMPLITUDE = 'amplitude'
FILTER_PASS = 'pass'
FILTER_STOP = 'stop'

def Timestamp2String(seconds, microseconds):
    return '%s,%06d' % (('%d/%02d/%02d %02d:%02d:%02d' % time.gmtime(seconds)[0:6]), microseconds)

def Frequency2Index(frequency, starting_frequency, frequency_resolution):
    return (frequency * 1000.0 - starting_frequency) * 1000.0 / frequency_resolution

def Index2Frequency(index, starting_frequency, frequency_resolution):
    return (index * frequency_resolution / 1000.0 + starting_frequency) / 1000.0

def RSSI2Amplitude(RSSI, amplitude_offset, amplitude_resolution):
    return (RSSI * amplitude_resolution + amplitude_offset) / 1000.0

def Amplitude2RSSI(amplitude, amplitude_offset, amplitude_resolution):
    return (amplitude * 1000.0 - amplitude_offset) / amplitude_resolution

def Main():
    """Tool for processing wi-spy wsr files
    """

    parser = OptionParser(usage='usage: %prog [options] infile outfile', version='%prog 0.2')
    parser.add_option('-f', '--filter', default=FILTER_PASS, help='type of filter to apply: pass for band-pass (default), stop for band-stop')
    parser.add_option('-l', '--lower', type='float', help='lower cutoff value (frequency in MHz, amplitude in dBm)')
    parser.add_option('-u', '--upper', type='float', help='upper cutoff value (frequency in MHz, amplitude in dBm)')
    parser.add_option('-p', '--parameter', default=PARAMETER_FREQUENCY, help='type of parameter (unit) to filter: frequency (default), amplitude')
    parser.add_option('-r', '--reduce', action='store_true', default=False, help='reduce sweep to frequency band-pass filter')
    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        print ''
        print '  Tool for processing wi-spy wsr files'
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'

    else:

        if not options.parameter in (PARAMETER_FREQUENCY, PARAMETER_AMPLITUDE):
            print 'unknown value for parameter: %s' % options.parameter
            return

        if not options.filter in (FILTER_PASS, FILTER_STOP):
            print 'unknown value for filter: %s' % options.filter
            return

        header = Struct('header', UBInt32('version_number'),
                                  UBInt16('device_version'),
                                  UBInt32('starting_frequency'),
                                  UBInt32('frequency_resolution'),
                                  UBInt16('readings_per_sweep'),
                                  SBInt32('amplitude_offset'),
                                  UBInt32('amplitude_resolution'),
                                  UBInt16('max_steps'),
                                  SBInt64('first_bookmark'))

        try:
            streamIn = open(args[0], 'rb')
        except:
            print "error reading file %s" % args[0]
            return

        try:
            cHeader = header.parse_stream(streamIn)
        except:
            print "error reading file %s" % args[0]
            return

        if options.parameter == PARAMETER_FREQUENCY:
            if options.lower == None:
                lower = 0
            else:
                lower = Frequency2Index(options.lower, cHeader.starting_frequency, cHeader.frequency_resolution)
            if options.upper == None:
                upper = cHeader.readings_per_sweep - 1
            else:
                upper = Frequency2Index(options.upper, cHeader.starting_frequency, cHeader.frequency_resolution)
            unit = UNIT_MHZ
        else:
            if options.lower == None:
                lower = 0
            else:
                lower = Amplitude2RSSI(options.lower, cHeader.amplitude_offset, cHeader.amplitude_resolution)
            if options.upper == None:
                upper = 255 #I believe this should be max_steps-1, but max_steps is 265
            else:
                upper = Amplitude2RSSI(options.upper, cHeader.amplitude_offset, cHeader.amplitude_resolution)
            unit = UNIT_DBM

        print 'Filter: band-%s' % options.filter
        if unit == UNIT_MHZ:
            print 'Lower cutoff value: %f %s' % (Index2Frequency(lower, cHeader.starting_frequency, cHeader.frequency_resolution), unit)
            print 'Upper cutoff value: %f %s' % (Index2Frequency(upper, cHeader.starting_frequency, cHeader.frequency_resolution), unit)
        else:
            print 'Lower cutoff value: %f %s' % (RSSI2Amplitude(lower, cHeader.amplitude_offset, cHeader.amplitude_resolution), unit)
            print 'Upper cutoff value: %f %s' % (RSSI2Amplitude(upper, cHeader.amplitude_offset, cHeader.amplitude_resolution), unit)
        print

        data_packetIn = Struct('data_packetIn', UBInt32('seconds'),
                                                UBInt32('microseconds'),
                                                StrictRepeater(cHeader.readings_per_sweep, Byte('raw_RSSI')))

        readings_per_sweep = cHeader.readings_per_sweep
        if options.reduce and options.parameter == PARAMETER_FREQUENCY and options.filter == FILTER_PASS:
            indexLower = int(lower)+1
            indexUpper = int(upper)
            cHeader.readings_per_sweep = indexUpper - indexLower + 1
            cHeader.starting_frequency = int(Index2Frequency(indexLower, cHeader.starting_frequency, cHeader.frequency_resolution)) * 1000

        data_packetOut = Struct('data_packetOut', UBInt32('seconds'),
                                                  UBInt32('microseconds'),
                                                  StrictRepeater(cHeader.readings_per_sweep, Byte('raw_RSSI')))

        try:
            streamOut = open(args[1], 'wb')
            streamOut.write(header.build(cHeader))
        except:
            streamIn.close()
            print "error writing file %s" % args[1]
            return

        print cHeader

        secondsFirstSample = None
        counterSamples = 0
        while streamIn.tell() < cHeader.first_bookmark:
            cData_packet = data_packetIn.parse_stream(streamIn)
            if options.parameter == PARAMETER_FREQUENCY:
                if options.filter == FILTER_PASS:
                    if options.reduce:
                        del cData_packet.raw_RSSI[indexUpper+1:]
                        del cData_packet.raw_RSSI[0:indexLower]
                    else:
                        for i in range(int(lower)+1):
                            cData_packet.raw_RSSI[i] = 0
                        for i in range(int(upper)+1, readings_per_sweep):
                            cData_packet.raw_RSSI[i] = 0
                else:
                    for i in range(int(lower)+1, int(upper)+1):
                        cData_packet.raw_RSSI[i] = 0
            else:
                for i, rawRSSI in enumerate(cData_packet.raw_RSSI):
                    between = lower <= cData_packet.raw_RSSI[i] and cData_packet.raw_RSSI[i] <= upper
                    if (options.filter == FILTER_PASS and not between) or (options.filter == FILTER_STOP and between):
                        cData_packet.raw_RSSI[i] = 0
            try:
                if options.reduce:
                    streamOut.write(data_packetOut.build(cData_packet))
                else:
                    streamOut.write(data_packetIn.build(cData_packet))
            except:
                streamIn.close()
                streamOut.close()
                print "error writing file %s" % args[1]
                return
            counterSamples += 1
            if secondsFirstSample == None:
                secondsFirstSample = cData_packet.seconds
                microsecondsFirstSample = cData_packet.microseconds
            secondsLastSample = cData_packet.seconds
            microsecondsLastSample = cData_packet.microseconds
            #t = '%d/%02d/%02d %02d:%02d:%02d' % time.gmtime(cData_packet.seconds)[0:6]
            #print '%s,%06d,%s' % (t, cData_packet.microseconds, ','.join(["%f" % ((rawRSSI*cHeader.amplitude_resolution+cHeader.amplitude_offset)/1000.0) for rawRSSI in cData_packet.raw_RSSI]))

        print
        print 'First sample: %s' % Timestamp2String(secondsFirstSample, microsecondsFirstSample)
        print 'Last sample:  %s' % Timestamp2String(secondsLastSample, microsecondsLastSample)
        print 'Sample count: %d' % counterSamples

        try:
            streamOut.write(streamIn.read())
        except:
            streamIn.close()
            streamOut.close()
            print "error writing file %s" % args[1]
            return
        
        if options.reduce:
            cHeader.first_bookmark = cHeader.first_bookmark - (readings_per_sweep - cHeader.readings_per_sweep ) * counterSamples
            try:
                streamOut.seek(0)
                streamOut.write(header.build(cHeader))
            except:
                streamIn.close()
                streamOut.close()
                print "error writing file %s" % args[1]
                return

        streamIn.close()
        streamOut.close()

if __name__ == '__main__':
    Main()
