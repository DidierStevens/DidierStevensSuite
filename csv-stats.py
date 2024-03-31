#!/usr/bin/env python

__description__ = 'Tool to produce statistics for CSV files'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2024/03/30'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2017/11/05: start
  2017/11/21: added options -m, -n
  2017/11/22: continue
  2017/11/24: renamed option -n to -l, added option -n; wrote man page
  2017/11/27: fixes for Python 3.5
  2018/07/21: added line numbers
  2024/03/30: refactor

Todo:
"""

import csv
import optparse
import os
import gzip
import glob
import signal
import collections
import sys
import textwrap

SEPARATOR = ','
QUOTE = '"'
KEY_ERROR = 'error'

def PrintManual():
    manual = '''
Manual:

This tool takes one or more CSV files as input and produces statistics (combined for all provided files).

The arguments to this command can be one or more filenames. If a provided file is a gzip compressed file (extension .gz), csv-stats.py will decompress the content of the file. Wildcards are supported (like data*.csv) and 'here-files' can be used. A here-file is a text file that contains a list of filenames. Each filename must be written on a separate line. Here-files are identified by prefixing their filename with a '@' characters, like this: @documents.txt
When no filename is provided as argument, input is read from stdin.

Let's take the following CSV file as example 1:
200,answer
206,answer
301,redirect
302,redirect
303,redirect
304,redirect
400,client error
401,client error
402,client error
403,client error
404,client error

This file has 11 rows, each with 2 fields (character , is the field separator). There is no header row.

Running the following command on this CSV file:
csv-stats.py example-1.csv

produces the following output:

Number of lines: 11
Minimum number of fields: 2
Maximum number of fields: 2
Minimum number of total characters in fields: 9
Maximum number of total characters in fields: 15

Field 0: 11 unique values
 200: 1
 206: 1
 301: 1
 302: 1
 303: 1
 ...
 404: 1
 403: 1
 402: 1
 401: 1
 400: 1

Field 1: 3 unique values
 client error: 5
 redirect: 4
 answer: 2

By default, csv-stats.py assumes that the field separator is the , character. You can use option -s to provide another separator character. To use a TAB character as separator, use \\t.

The first lines of output characterize the provide input file(s). First we have the total number of lines, and then the number of fields. Since we can have CSV files where the number of fields varies from line to line, csv-stats.py reports the smallest and largest number of fields found in a row.
After that we totalize all characters in all fields per row, and provide the minimum and maximum number of total characters.

Next, the content of each field is analyzed. Fields are numbered starting from 0, and csv-stats.py provides the number of unique values found for each field, together with a report of the values.
If the number of values is equal to or lower than 10, then all values are listed, together with the number of times they occur, sorted from most frequent to least frequent.
If there are more than 10 values, then the 5 most frequent and 5 least frequent are listed.
This limit, 10, can be changed with option -l. For example, to print up to 20 values, use option -l 20.

By default, the output produced by csv-stats.py is printed to stdout. It can be written to a file using option -o, for example -o report.txt to write the report to file report.txt.

csv-stats.py can also handle CSV files with a header, like this file: example-2.csv

Code,Type
200,answer
206,answer
301,redirect
302,redirect
303,redirect
304,redirect
400,client error
401,client error
402,client error
403,client error
404,client error

By default, csv-stats.py does not assume the provided input files have headers. To recognize the first row of each input file as a header row, use option -H, like this:

csv-stats.py -H example-2.csv

Number of lines: 11
Minimum number of fields: 2
Maximum number of fields: 2
Minimum number of total characters in fields: 9
Maximum number of total characters in fields: 15

Field Code: 11 unique values
 200: 1
 206: 1
 301: 1
 302: 1
 303: 1
 ...
 404: 1
 403: 1
 402: 1
 401: 1
 400: 1

Field Type: 3 unique values
 client error: 5
 redirect: 4
 answer: 2

The output is almost identical to the analysis of file example-1.csv, except that the fields have a name in stead of a number. The field name is obtained from the header row.

By default, csv-stats.py reads and analyses all rows in all provided files. This can take quite some time with large files, therefor option -n can be used to limit the number of lines to be read.
Example to read 5 lines:

csv-stats.py -H -n 5 example-2.csv

Number of lines: 5
Minimum number of fields: 2
Maximum number of fields: 2
Minimum number of total characters in fields: 9
Maximum number of total characters in fields: 11

Field Code: 5 unique values
 200: 1
 301: 1
 303: 1
 302: 1
 206: 1

Field Type: 2 unique values
 redirect: 3
 answer: 2

Option -n can be used to speed up analysis and get a first impression of what kind CSV files are being analyzed.

Errors occuring during the analysis of the CSV files will be silently ignored. This is good for a first analysis, but it is also important to know that CSV files do not contain content will generate errors when analzyed.
Use option -R to raise errors when errors occur. This will allow you to confirm that the CSV files are clean.

When a field contains a separator character that is not a separator, the field must be properly quoted, like this: 200,"ans,wer".
csv-stats.py handles quoted fields properly, but this can be supressed using option -U. When option -U is used, quotes have no special meaning.

Finally, option -e can be used to exclude selected fields from analysis. This can be useful when the CSV files are very large and would take up too much memory from the Python interpreter. Then it can help by excluding fields with many unique values.
Option -e takes a field number or a field name (when option -H is used), and when several fields are to be excluded, they are separated by the same separator as given with option -s or the , character.
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

class cOutput():
    def __init__(self, filename=None, binary=False):
        self.binary = binary
        self.filename = filename
        self.header = None
        self.dFiles = {}
        if self.filename and self.filename != '':
            if self.binary:
                self.f = open(self.filename, 'wb')
            else:
                self.f = open(self.filename, 'w')
        else:
            self.f = None
            if self.binary:
                IfWIN32SetBinary(sys.stdout)

    def Header(self, line, noprint=False):
        self.header = line
        if not noprint:
            self.Line(line)

    def Line(self, line, filename=None):
        if filename == None:
            if self.binary:
                if self.f:
                    self.f.write(line)
                else:
                    StdoutWriteChunked(line)
            else:
                if self.f:
                    self.f.write(line + '\n')
                else:
                    print(line)
        else:
            if not filename in self.dFiles:
                if self.binary:
                    self.dFiles[filename] = open(filename, 'wb')
                else:
                    self.dFiles[filename] = open(filename, 'w')
                if self.header != None:
                    if self.binary:
                        self.dFiles[filename].write(self.header)
                    else:
                        self.dFiles[filename].write(self.header + '\n')
            if self.binary:
                self.dFiles[filename].write(line)
            else:
                self.dFiles[filename].write(line + '\n')

    def Close(self):
        for fOut in self.dFiles.values():
            fOut.close()
        if self.f:
            self.f.close()
            self.f = None

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

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

def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def ConvertHeaderToIndex(header, separator, columns):
    try:
        result = []
        for column in columns.split(separator):
            result.append(header.index(column))
        return result
    except:
        return None

def IntegerOrNone2String(value, linenumber):
    if value == None:
        return 'None'
    else:
        return '%d (line %d)' % (value, linenumber)

def CSVStats(files, options):
    FixPipe()
    if options.exclude == '':
        columnsIndices = []
    else:
        if options.separator in options.exclude:
            columnsToExclude = [column for column in options.exclude.split(options.separator)]
        else:
            columnsToExclude = [column for column in options.exclude.split(SEPARATOR)]
        columnsIndices = None
        if not options.header:
            columnsIndices = [int(columnIndex) for columnIndex in columnsToExclude]
    if options.output:
        oOutput = cOutput(options.output)
    else:
        oOutput = cOutput()
    headerPrinted = False

    counter = 0
    rowMinimumTotalCharacters = None
    rowMaximumTotalCharacters = None
    rowMinimumNumberOfFields = None
    rowMaximumNumberOfFields = None
    rowMinimumTotalCharactersCounter = None
    rowMaximumTotalCharactersCounter = None
    rowMinimumNumberOfFieldsCounter = None
    rowMaximumNumberOfFieldsCounter = None
    dValues = {}
    dValuesInt = {}

    for file in files:
        if file == '':
            fIn = sys.stdin
        elif os.path.splitext(file)[1].lower() == '.gz':
            fIn = gzip.open(file, 'rt')
        else:
            fIn = open(file, 'r', encoding='utf8')
        reader = csv.reader(fIn, delimiter=options.separator, skipinitialspace=False, quoting=IFF(options.unquoted, csv.QUOTE_NONE, csv.QUOTE_MINIMAL))
        firstRow = True
        headerRow = None
        for row in reader:
            if options.number > 0 and counter >= options.number:
                break
            try:
                if options.ignore != '' and len(row) > 0 and row[0].startswith(options.ignore):
                    continue
                if options.header and firstRow:
                    firstRow = False
                    headerRow = row
                    if columnsIndices == None:
                        columnsIndices = ConvertHeaderToIndex(row, options.separator, options.exclude)
                    if columnsIndices == None:
                        print('Columns to exclude "%s" not found in file %s' % (options.exclude, file))
                        return
                    continue
                counter += 1
                if rowMinimumNumberOfFields == None or rowMinimumNumberOfFields > len(row):
                    rowMinimumNumberOfFields = len(row)
                    rowMinimumNumberOfFieldsCounter = counter
                if rowMaximumNumberOfFields == None or rowMaximumNumberOfFields < len(row):
                    rowMaximumNumberOfFields = len(row)
                    rowMaximumNumberOfFieldsCounter = counter
                rowTotalCharacters = sum(map(len, row))
                if rowMinimumTotalCharacters == None or rowMinimumTotalCharacters > rowTotalCharacters:
                    rowMinimumTotalCharacters = rowTotalCharacters
                    rowMinimumTotalCharactersCounter = counter
                if rowMaximumTotalCharacters == None or rowMaximumTotalCharacters < rowTotalCharacters:
                    rowMaximumTotalCharacters = rowTotalCharacters
                    rowMaximumTotalCharactersCounter = counter
                for index, field in enumerate(row):
                    if index not in columnsIndices:
                        if index in dValues:
                            dValues[index][field] = dValues[index].get(field, 0) + 1
                        else:
                            dValues[index] = {field:1}
                        try:
                            fieldInt = int(field)
                        except ValueError:
                            fieldInt = KEY_ERROR
                        if index in dValuesInt:
                            dValuesInt[index][fieldInt] = dValuesInt[index].get(fieldInt, 0) + 1
                        else:
                            if fieldInt == KEY_ERROR:
                                dValuesInt[index] = {KEY_ERROR: 1}
                            else:
                                dValuesInt[index] = {fieldInt: 1, KEY_ERROR: 0}
            except KeyboardInterrupt:
                raise
            except:
                if options.raiseerror:
                    raise

        if fIn != sys.stdin:
            fIn.close()

    oOutput.Line('Number of lines: %d' % counter)
    oOutput.Line('Minimum number of fields: %s' % IntegerOrNone2String(rowMinimumNumberOfFields, rowMinimumNumberOfFieldsCounter))
    oOutput.Line('Maximum number of fields: %s' % IntegerOrNone2String(rowMaximumNumberOfFields, rowMaximumNumberOfFieldsCounter))
    oOutput.Line('Minimum number of total characters in fields: %s' % IntegerOrNone2String(rowMinimumTotalCharacters, rowMinimumTotalCharactersCounter))
    oOutput.Line('Maximum number of total characters in fields: %s' % IntegerOrNone2String(rowMaximumTotalCharacters, rowMaximumTotalCharactersCounter))
    oOutput.Line('')

    if rowMaximumNumberOfFields != None:
        dValuesIntWithoutError = {}
        for index in range(rowMaximumNumberOfFields):
            if not index in columnsIndices:
                if headerRow == None:
                    oOutput.Line('Field %d: %d unique values, %d unique integer values %d error(s)' % (index, len(dValues[index]), len(dValuesInt[index]) - 1, dValuesInt[index].get(KEY_ERROR, 0)))
                else:
                    oOutput.Line('Field %s: %d unique values, %d unique integer values %d error(s)' % (headerRow[index], len(dValues[index]), len(dValuesInt[index]) - 1, dValuesInt[index].get(KEY_ERROR, 0)))
                sorted_items = sorted(dValues[index].items(), key=lambda x: x[1], reverse=True)
                if len(sorted_items) <= options.limit:
                    for key, value in list(sorted_items)[0:options.limit]:
                        oOutput.Line(' %s: %d' % (key, value))
                else:
                    for key, value in list(sorted_items)[0:int(options.limit/2)]:
                        oOutput.Line(' %s: %d' % (key, value))
                    oOutput.Line(' ...')
                    for key, value in list(sorted_items)[-int(options.limit/2):]:
                        oOutput.Line(' %s: %d' % (key, value))
                dValuesIntWithoutError[index] = dValuesInt[index].copy()
                del dValuesIntWithoutError[index][KEY_ERROR]
                if headerRow == None:
                    oOutput.Line('Field %d: minimum: %s' % (index, min(dValues[index])))
                    oOutput.Line('Field %d: maximum: %s' % (index, max(dValues[index])))
                    if len(dValuesIntWithoutError[index]) > 0:
                        oOutput.Line('Field %d: minimum integer: %s' % (index, min(dValuesIntWithoutError[index])))
                        oOutput.Line('Field %d: maximum integer: %s' % (index, max(dValuesIntWithoutError[index])))
                else:
                    oOutput.Line('Field %s: minimum: %s' % (headerRow[index], min(dValues[index])))
                    oOutput.Line('Field %s: maximum: %s' % (headerRow[index], max(dValues[index])))
                    if len(dValuesIntWithoutError[index]) > 0:
                        oOutput.Line('Field %s: minimum integer: %s' % (headerRow[index], min(dValuesIntWithoutError[index])))
                        oOutput.Line('Field %s: maximum integer: %s' % (headerRow[index], max(dValuesIntWithoutError[index])))
                oOutput.Line('')

    oOutput.Close()

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [[@]files]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--separator', default=SEPARATOR, help='Separator character (default %s)' % SEPARATOR)
    oParser.add_option('-o', '--output', help='Output to file')
    oParser.add_option('-e', '--exclude', default='', help='Columns to exclude')
    oParser.add_option('-n', '--number', type=int, default=0, help='Number of lines to process (default is to process all lines)')
    oParser.add_option('-l', '--limit', type=int, default=10, help='Number of items to list (default is limit items to 10)')
    oParser.add_option('-H', '--header', action='store_true', default=False, help='Header')
    oParser.add_option('-U', '--unquoted', action='store_true', default=False, help='No handling of quotes in CSV file')
    oParser.add_option('-R', '--raiseerror', action='store_true', default=False, help='Raise error when error occurs')
    oParser.add_option('-i', '--ignore', default='', help='Ignore lines that start with given string')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if options.number < 0:
        print('Option -n --number must be a positive number')
        return

    if options.limit < 2:
        print('Option -l --limit must be at least 2')
        return

    if options.separator == r'\t':
        options.separator = '\t'
    if options.separator == '\t' and r'\t' in options.exclude:
        options.exclude = options.exclude.replace(r'\t', '\t')
    if len(args) == 0:
        files = ['']
    else:
        files = ExpandFilenameArguments(args)
    CSVStats(files, options)

if __name__ == '__main__':
    Main()
