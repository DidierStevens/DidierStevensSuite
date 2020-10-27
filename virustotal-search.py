#!/usr/bin/env python

__description__ = 'Program to search VirusTotal reports with search terms (MD5, SHA1, SHA256, URL) found in the argument file'
__author__ = 'Didier Stevens'
__version__ = '0.1.6'
__date__ = '2020/10/18'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2012/04/25: start
  2012/04/27: added serialization of reports
  2012/05/23: emergency fix pkl init bug
  2012/05/26: 0.0.3 added force option and key option; added environment variable; added requested field
  2012/12/17: 0.0.4 added proxy and option insecure
  2013/02/22: 0.0.5 added InsecureJSONParsing
  2013/03/15: 0.0.6 added json; removed option insecure and InsecureJSONParsing
  2013/04/19: 0.0.7 refactoring; proxies
  2013/04/29: 0.0.8 added option globaldb
  2013/06/10: 0.0.9 fixed bug for print None with CN, thanks Mark Woan
  2013/06/17: added exception handling for jsonalias.loads
  2013/11/26: 0.1.0 update to perform up to 4 searchs per request
  2013/11/27: bugfix pkl
  2014/01/19: 0.1.1 added option -m
  2014/01/21: added 204 handling
  2014/01/26: added option -u
  2014/01/28: stripping \r\n from search terms
  2014/01/30: added option -o
  2014/02/05: added pickle functions for dictionary; options -r -a
  2014/02/09: added option -n
  2014/09/01: added option -i
  2015/01/19: added option -w
  2015/01/26: added option -R
  2015/04/23: 0.1.2 added CVE (thanks Pieter-Jan Moreels)
  2015/08/11: 0.1.3 added option -s
  2016/01/17: 0.1.4 added support for stdin
  2019/01/07: 0.1.5 added option -e, -t
  2020/10/18: 0.1.6 Python 3 update (Python 2 no longer supported)

Todo:
"""

import optparse
import urllib
import urllib.request
#import urllib2
import time
import sys
import pickle
import os
import traceback
import hashlib
import random
import re

try:
    import json
    jsonalias = json
except:
    try:
        import simplejson
        jsonalias = simplejson
    except:
        print('Modules json and simplejson missing')
        exit()

VIRUSTOTAL_API2_KEY = ''
HTTP_PROXY = ''
HTTPS_PROXY = ''

VIRUSTOTAL_REPORT_URL = {'file': 'https://www.virustotal.com/vtapi/v2/file/report', 'url': 'https://www.virustotal.com/vtapi/v2/url/report'}
VIRUSTOTAL_REPORT_SEPARATOR = {'file': ',', 'url': '\n'}

PICKLE_FILE = 'virustotal-search.pkl'

#CN = ConvertNone
def CN(value, stringNone=''):
    if value == None:
        return stringNone
    else:
        return value

def Serialize(filename, object):
    try:
        fPickle = open(filename, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle, -1)
    except:
        print(sys.exc_info())
        return False
    finally:
        fPickle.close()
    return True

def SerializeDictionary(filename, dInput):
    try:
        fPickle = open(filename, 'wb')
    except:
        return False
    try:
        for item in dInput.items():
            pickle.dump(item, fPickle, -1)
    except:
        print(sys.exc_info())
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize(filename):
    import os.path

    if os.path.isfile(filename):
        try:
            fPickle = open(filename, 'rb')
        except:
            return None
        try:
            object = pickle.load(fPickle)
        except:
            return None
        finally:
            fPickle.close()
        return object
    else:
        return None

def DeSerializeDictionary(filename):
    import os.path

    dReturn = {}
    if os.path.isfile(filename):
        try:
            fPickle = open(filename, 'rb')
        except:
            return None
        try:
            while True:
                item = pickle.load(fPickle)
                dReturn[item[0]] = item[1]
        except EOFError:
            pass
        except:
            print(sys.exc_info())
            return None
        finally:
            fPickle.close()
        return dReturn
    else:
        return None

def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]

class CSVLogger():
    def __init__(self, prefix, headers, separator=';', prefixIsFullName=False):
        self.separator = separator
        if prefixIsFullName:
            self.filename = prefix
        else:
            self.filename = '%s-%s.csv' % (prefix, Timestamp())
        self.f = open(self.filename, 'w')
        self.f.write(self.separator.join(headers) + '\n')
        self.f.close()

    def PrintAndLog(self, formats, parameters):
        line = self.separator.join(formats) % parameters
        print(line)
        f = open(self.filename, 'a')
        f.write(line + '\n')
        f.close()

def VTHTTPReportRequest(searchTerm, type):
    global VIRUSTOTAL_API2_KEY

    statuscode = 0
    req = urllib.request.Request(VIRUSTOTAL_REPORT_URL[type], urllib.parse.urlencode({'resource': searchTerm, 'apikey': VIRUSTOTAL_API2_KEY}).encode('utf-8'))
    try:
        if sys.hexversion >= 0x020601F0:
            hRequest = urllib.request.urlopen(req, timeout=15)
        else:
            hRequest = urllib.request.urlopen(req)
    except:
        return statuscode, None
    try:
        statuscode = hRequest.getcode()
        data = hRequest.read()
    except:
        return statuscode, None
    finally:
        hRequest.close()
    return statuscode, data

def InsertIntoTuple(tupleIn, position, value):
    listIn = list(tupleIn)
    listIn.insert(position, value)
    return tuple(listIn)

def ParseSearchterm(searchTerm, withComment):
    comment = None
    if withComment:
        index = searchTerm.find(' ')
        if index == -1:
            comment = ''
        else:
            try:
                comment = searchTerm[index + 1:]
            except:
                comment = ''
            searchTerm = searchTerm[:index]
    return (searchTerm, comment)

def LogResult(searchTerm, comment, oResult, issuedRequest, withComment, extra):
    global oLogger

    if oResult['response_code'] == 1:
        scans = []
        cves = []
        reCVE = re.compile(r'(CVE([_-])\d{4}\2\d{4,5})')
        for scan in sorted(oResult['scans']):
            if oResult['scans'][scan]['detected']:
                result = [scan, oResult['scans'][scan]['result']]
                if type == 'file':
                    result.extend([oResult['scans'][scan]['update'], oResult['scans'][scan]['version']])
                scans.append('#'.join(map(CN, result)))
            if oResult['scans'][scan]['result']:
                cves += [cve[0].upper().replace('_', '-') for cve in reCVE.findall(oResult['scans'][scan]['result'])]
        formats = ('%s', '%d', '%d', '%s', '%d', '%d', '%s', '%s', '%s')
        parameters = (searchTerm, issuedRequest, oResult['response_code'], oResult['scan_date'], oResult['positives'], oResult['total'], oResult['permalink'], ','.join(scans), ','.join(sorted(list(set(cves)))))
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        for e in extra:
            formats = formats + ('%s', )
            parameters = parameters + (oResult[e], )
        oLogger.PrintAndLog(formats, parameters)
    else:
        formats = ('%s', '%d', '%d', '%s')
        parameters = (searchTerm, issuedRequest, oResult['response_code'], oResult['verbose_msg'])
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)

def GetReports(searchTerms, reports, withComment, extra, type, dNotFound=None):
    global oLogger

    searchTermComments = [ParseSearchterm(searchTerm, withComment) for searchTerm in searchTerms]

    searchTerm = VIRUSTOTAL_REPORT_SEPARATOR[type].join([searchTermComment[0] for searchTermComment in searchTermComments])
    if withComment:
        comments = VIRUSTOTAL_REPORT_SEPARATOR[type].join([searchTermComment[1] for searchTermComment in searchTermComments])
    statuscode, jsonResponse = VTHTTPReportRequest(searchTerm, type)
    if jsonResponse == None or statuscode != 200:
        formats = ('%s', '%s', '%d')
        parameters = (searchTerm, 'Error VTHTTPReportRequest', statuscode)
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comments)
        oLogger.PrintAndLog(formats, parameters)
        return statuscode

    try:
        if len(searchTerms) == 1:
            oResults = [jsonalias.loads(jsonResponse)]
        else:
            oResults = jsonalias.loads(jsonResponse)
    except:
        formats = ('%s', '%s', '%s', '%s')
        parameters = (searchTerm, 'Error jsonalias.loads', sys.exc_info()[1], repr(traceback.format_exc()))
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comments)
        oLogger.PrintAndLog(formats, parameters)
        return statuscode

    for iIter in range(len(searchTerms)):
        if oResults[iIter]['response_code'] == 1:
            reports[searchTermComments[iIter][0]] = oResults[iIter]
        elif oResults[iIter]['response_code'] == 0 and dNotFound != None and not searchTermComments[iIter][0] in dNotFound:
            dNotFound[searchTermComments[iIter][0]] = True
        LogResult(searchTermComments[iIter][0], searchTermComments[iIter][1], oResults[iIter], True, withComment, extra)
    return statuscode

def File2Strings(filename):
    try:
        if filename == '':
            f = sys.stdin
        else:
            f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        if f != sys.stdin:
            f.close()

def Strings2File(filename, lines):
    try:
        f = open(filename, 'w')
    except:
        return None
    try:
        for line in lines:
            f.write(line + '\n')
        return True
    except:
        return None
    finally:
        f.close()

def SetProxiesIfNecessary():
    global HTTP_PROXY
    global HTTPS_PROXY

    dProxies = {}
    if HTTP_PROXY != '':
        dProxies['http'] = HTTP_PROXY
    if HTTPS_PROXY != '':
        dProxies['https'] = HTTPS_PROXY
    if os.getenv('http_proxy') != None:
        dProxies['http'] = os.getenv('http_proxy')
    if os.getenv('https_proxy') != None:
        dProxies['https'] = os.getenv('https_proxy')
    if dProxies != {}:
        urllib.install_opener(urllib.build_opener(urllib.ProxyHandler(dProxies)))

def GetPickleFile(globaldb):
    if globaldb:
        return os.path.join(os.path.dirname(sys.argv[0]), PICKLE_FILE)
    else:
        return PICKLE_FILE

def VirusTotalUpdate(filename, options):
    databaseFilename = GetPickleFile(options.globaldb)
    reports = DeSerializeDictionary(databaseFilename)
    if reports == None:
        print('No database found: %s' % databaseFilename)
        reports = {}
        return
    else:
        print('Database loaded: %d elements %s' % (len(reports), databaseFilename))

    reportsToMerge = DeSerializeDictionary(filename)
    if reportsToMerge == None:
        print('No database found: %s' % filename)
        reportsToMerge = {}
    else:
        print('Database loaded: %d elements %s' % (len(reportsToMerge), filename))

    countAdded = 0
    countUpdated = 0
    for key, value in reportsToMerge.items():
        if not key in reports:
            reports[key] = value
            countAdded += 1
        elif value['scan_date'] > reports[key]['scan_date']:
            reports[key] = value
            countUpdated += 1
    print('Records added: %d' % countAdded)
    print('Records updated: %d' % countUpdated)

    reportsToMerge = None
    if countAdded > 0 or countUpdated > 0:
        if SerializeDictionary(databaseFilename, reports):
            print('Database saved: %s' % databaseFilename)
        else:
            print('Error saving database: %s' % databaseFilename)

def VirusTotalRefresh(options):
    global oLogger

    SetProxiesIfNecessary()

    headers = ('Search Term', 'Requested', 'Response', 'Scan Date', 'Detections', 'Total', 'Permalink', 'AVs', 'CVEs')
    headers = headers + tuple(options.extra)
    if options.output:
        oLogger = CSVLogger(options.output, headers, separator=options.separator, prefixIsFullName=True)
    else:
        oLogger = CSVLogger('virustotal-search', headers, separator=options.separator)

    reports = DeSerializeDictionary(GetPickleFile(options.globaldb))
    if reports == None:
        reports = {}

    dateshashes = sorted([(value['scan_date'], key) for key, value in reports.items()])
    searchTermsToRequest = [hash for date, hash in dateshashes if date >= options.after]

    if options.refreshrandom:
        random.shuffle(searchTermsToRequest)

    while searchTermsToRequest != []:
        statuscode = GetReports(searchTermsToRequest[0:4], reports, options.comment, options.extra, options.type)
        if statuscode == 204:
            break
        searchTermsToRequest = searchTermsToRequest[4:]
        if searchTermsToRequest != []:
            time.sleep(options.delay)
    SerializeDictionary(GetPickleFile(options.globaldb), reports)

def VirusTotalSearch(filename, options):
    global oLogger

    SetProxiesIfNecessary()

    if options.md5:
        if filename == '':
            if sys.platform == 'win32':
                import msvcrt
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            data = sys.stdin.read()
        else:
            data = open(filename, 'rb').read()
        searchTerms = [hashlib.md5(data).hexdigest()]
    else:
        searchTerms = File2Strings(filename)
        if searchTerms == None:
            print('Error reading file %s' % filename)
            return
        elif searchTerms == []:
            print('No searchterms in file %s' % filename)
            return

    headers = ('Search Term', 'Requested', 'Response', 'Scan Date', 'Detections', 'Total', 'Permalink', 'AVs', 'CVEs')
    if options.comment:
        headers = InsertIntoTuple(headers, 1, 'Comment')
    headers = headers + tuple(options.extra)
    if options.output:
        oLogger = CSVLogger(options.output, headers, separator=options.separator, prefixIsFullName=True)
    else:
        oLogger = CSVLogger('virustotal-search', headers, separator=options.separator)

    reports = DeSerializeDictionary(GetPickleFile(options.globaldb))
    if reports == None:
        reports = {}

    dNotFound = None
    searchTerms = [searchTerm.rstrip('\r\n') for searchTerm in searchTerms]
    searchTermsToRequest = []
    if options.force:
        searchTermsToRequest = searchTerms
    else:
        for searchTermIter in searchTerms:
            searchTerm, comment = ParseSearchterm(searchTermIter, options.comment)
            if searchTerm in reports:
                LogResult(searchTerm, comment, reports[searchTerm], False, options.comment, options.extra)
            else:
                searchTermsToRequest.append(searchTermIter)
        if options.notfound:
            dNotFound = {}
            searchtermsNotfound = File2Strings(options.notfound)
            if searchtermsNotfound == None:
                searchtermsNotfound = []
            for searchtermNotfound in searchtermsNotfound:
                dNotFound[searchtermNotfound] = True
            searchTerms = searchTermsToRequest
            searchTermsToRequest = []
            for searchTermIter in searchTerms:
                searchTerm, comment = ParseSearchterm(searchTermIter, options.comment)
                if searchTerm in searchtermsNotfound:
                    LogResult(searchTerm, comment, {'response_code': 0, 'verbose_msg': 'The requested resource is not among the finished, queued or pending scans'}, False, options.comment, options.extra)
                else:
                    searchTermsToRequest.append(searchTermIter)

    while searchTermsToRequest != []:
        statuscode = GetReports(searchTermsToRequest[0:4], reports, options.comment, options.extra, options.type, dNotFound)
        if statuscode == 204 and not options.waitquota:
            break
        if statuscode == 204:
            time.sleep(60 * 60)
        else:
            searchTermsToRequest = searchTermsToRequest[4:]
            if searchTermsToRequest != []:
                time.sleep(options.delay)
    if options.notfound:
        Strings2File(options.notfound, dNotFound.keys())
    if not options.noupdate:
        SerializeDictionary(GetPickleFile(options.globaldb), reports)

def Main():
    global VIRUSTOTAL_API2_KEY

    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--delay', type=int, default=16, help='delay in seconds between queries (default 16s, VT rate limit is 4 queries per minute)')
    oParser.add_option('-c', '--comment', action='store_true', default=False, help='the search term is followed by a comment and separated by a space character')
    oParser.add_option('-f', '--force', action='store_true', default=False, help='force all request to be send to VirusTotal, even if found in local database (pkl file)')
    oParser.add_option('-k', '--key', default='', help='VirusTotal API key')
    oParser.add_option('-g', '--globaldb', action='store_true', default=False, help='use global database (pkl file) in same directory as program')
    oParser.add_option('-m', '--md5', action='store_true', default=False, help='calculate the md5 of the file and search it')
    oParser.add_option('-u', '--update', action='store_true', default=False, help='update the database (pkl file) with the provided database')
    oParser.add_option('-o', '--output', default='', help='Output to file')
    oParser.add_option('-r', '--refresh', action='store_true', default=False, help='refresh the database sequentially')
    oParser.add_option('-R', '--refreshrandom', action='store_true', default=False, help='refresh the database randomly')
    oParser.add_option('-a', '--after', default='1970-01-01', help='Date to start refreshing (default 1970-01-01)')
    oParser.add_option('-n', '--notfound', default='', help='File to keep track and skip not found searches')
    oParser.add_option('-i', '--noupdate', action='store_true', default=False, help='do not update the database') # i = immutable
    oParser.add_option('-w', '--waitquota', action='store_true', default=False, help='wait 1 hour when quota exceeded')
    oParser.add_option('-s', '--separator', default=';', help='Separator character (default ;)')
    oParser.add_option('-e', '--extra', default='', help='Extra fields to include (use , as separator)')
    oParser.add_option('-t', '--type', default='file', help='Type of resource to query (file, url)')
    (options, args) = oParser.parse_args()

    if not (len(args) <= 1 or (options.refresh or options.refreshrandom) and len(args) == 0):
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    if options.extra == '':
        options.extra = []
    else:
        options.extra = options.extra.split(',')
    if options.update:
        VirusTotalUpdate(args[0], options)
        return
    if os.getenv('VIRUSTOTAL_API2_KEY') != None:
        VIRUSTOTAL_API2_KEY = os.getenv('VIRUSTOTAL_API2_KEY')
    if options.key != '':
        VIRUSTOTAL_API2_KEY = options.key
    if VIRUSTOTAL_API2_KEY == '':
        print('You need to get a VirusTotal API key and set environment variable VIRUSTOTAL_API2_KEY, use option -k or add it to this program.\nTo get your API key, you need a VirusTotal account.')
    elif options.refresh or options.refreshrandom:
        VirusTotalRefresh(options)
    elif len(args) == 0:
        VirusTotalSearch('', options)
    else:
        VirusTotalSearch(args[0], options)

if __name__ == '__main__':
    Main()
