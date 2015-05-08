#!/usr/bin/python
"""

Tool to log archive video surveillance pictures

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/06/26: start
  2009/02/12: V0.2 update
  2009/02/13: copy picture to ftp upload directory
  2009/02/15: config files, scheduler
  2011/05/31: V0.3 added queues to process retrieval of pictures, one thread per picture URL
  2011/06/01: V0.4 changed queue system
  2012/01/07: V0.5 Added command per picture
"""

__author__ = 'Didier Stevens'
__version__ = '0.5'
__date__ = '2012/01/07'

import urllib2
import zlib
import pickle
import os
import time
import shutil
import sched
import optparse
import sys
import threading
import Queue
import subprocess

#PROXY = 'http://webproxy:8000'

PICKLE_FILE = 'vs.pkl'
VS_CONFIG = 'vs.config'
CREDENTIALS_CONFIG = 'credentials.config'

class cPictureData:
    """manage picture data
    """

    def __init__(self, name, url, copy, threadName, command=None):
        self.name = name
        self.url = url
        self.copy = copy
        self.crc32 = None
        if threadName == '':
            threadName = '<DEFAULT>'
        self.threadName = threadName
        self.command = command

def Config2List(fileName):
    try:
        configFile = open(fileName, 'r')
    except:
        return None
    try:
        config = [line.rstrip('\n').split('\t') for line in configFile.readlines()]
    except:
        pass
    finally:
        configFile.close()
    return config

def WriteBinaryFile(name, content):
    try:
        fBinary = open(name, 'wb')
    except:
        return False
    try:
        fBinary.write(content)
    except:
        return False
    finally:
        fBinary.close()
    return True

def HTTPRequest(url):
    try:
        if sys.hexversion >= 0x020601F0:
            hPicture = urllib2.urlopen(url, timeout=5)
        else:
            hPicture = urllib2.urlopen(url)
    except:
        return None
    try:
        data = hPicture.read()
    except:
        return None
    finally:
        hPicture.close()
    return data

def PictureArchive(oPicture, archiveDirectory):
    """Download picture, compare and archive new picture
    """

    global oSynchroPrint

    urlsSplitted = oPicture.url.split(' ')
    if len(urlsSplitted) == 1:
        picture = HTTPRequest(urlsSplitted[0])
    else:
        HTTPRequest(urlsSplitted[0])
        time.sleep(3)
        picture = HTTPRequest(urlsSplitted[1])
    if picture == None:
        return None

    crc32 = zlib.crc32(picture)
    if oPicture.crc32 == None or oPicture.crc32 != crc32:
        oPicture.crc32 = crc32
        now = '%04d%02d%02d-%02d%02d%02d' % time.localtime()[0:6]
        splitBaseExt = os.path.splitext(oPicture.name)
        name = '%s\\%s-%s%s' % (archiveDirectory, splitBaseExt[0], now, splitBaseExt[1])
        WriteBinaryFile(name, picture)
        oSynchroPrint.Print('%s %d' % (name, oPicture.crc32))
        return name
    else:
        return None

def Serialize(object):
    global PICKLE_FILE

    try:
        fPickle = open(PICKLE_FILE, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize():
    global PICKLE_FILE

    if os.path.isfile(PICKLE_FILE):
        try:
            fPickle = open(PICKLE_FILE, 'rb')
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

def ConfigureUrllib2():
    #http://www.voidspace.org.uk/python/articles/authentication.shtml

    global CREDENTIALS_CONFIG

    oPasswordMgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    for credentials in Config2List(CREDENTIALS_CONFIG):
        oPasswordMgr.add_password(None, credentials[0], credentials[1], credentials[2])
    oBasicAuthHandler = urllib2.HTTPBasicAuthHandler(oPasswordMgr)
    if 'PROXY' in locals():
        oProxyHandler = urllib2.ProxyHandler({'http': PROXY})
        oOpener = urllib2.build_opener(oBasicAuthHandler, oProxyHandler)
    else:
        oOpener = urllib2.build_opener(oBasicAuthHandler)
    urllib2.install_opener(oOpener)

def ProcessPictures(sch, delay, pictures, archiveDirectoryPrefix, ftpDirectory):
    global dQueues
    global oSynchroPrint

    sch.enter(delay, 1, ProcessPictures, [sch, delay, pictures, archiveDirectoryPrefix, ftpDirectory])

    archiveDirectory = archiveDirectoryPrefix + '-%04d%02d%02d' % time.localtime()[0:3]
    if not os.path.isdir(archiveDirectory):
        os.makedirs(archiveDirectory)
        oSynchroPrint.Print('Created directory %s' % archiveDirectory)

    for oPicture in pictures:
        dQueues[oPicture.threadName].put((oPicture, archiveDirectory, ftpDirectory))

def HTTPWorker(threadName, queue):
    global oSynchroPrint

    oSynchroPrint.Print('HTTPWork thread started: %s' % threadName)
    while True:
        command = queue.get()
        oPicture = command[0]
        archiveDirectory = command[1]
        ftpDirectory = command[2]
        fileName = PictureArchive(oPicture, archiveDirectory)
        if fileName != None:
            if oPicture.copy != '-':
                try:
                    shutil.copyfile(fileName, os.path.join(ftpDirectory, oPicture.copy))
                except:
                    pass
            if oPicture.command != None:
                command = '%s %s' % (oPicture.command, os.path.join(ftpDirectory, oPicture.copy))
                oSynchroPrint.Print('Launch command: %s' % command)
                try:
                    subprocess.Popen(command)
                except:
                    oSynchroPrint.Print('Launch failed')
        queue.task_done()

def StartDaemon(function, threadName, queue):
    oThread = threading.Thread(target=function, args=[threadName, queue])
    oThread.setDaemon(True)
    oThread.start()

def CreateQueueAndDaemons(pictures):
    global dQueues

    for oPicture in pictures:
        if not oPicture.threadName in dQueues:
            dQueues[oPicture.threadName] = Queue.Queue()
            StartDaemon(HTTPWorker, oPicture.threadName, dQueues[oPicture.threadName])

class cSynchroPrint:
    def __init__(self):
        self.oLock = threading.Lock()

    def Print(self, string):
        self.oLock.acquire()
        try:
            print(string)
        finally:
            self.oLock.release()

def Main():
    """Tool to log archive video surveillance pictures
    """

    global VS_CONFIG
    global PICKLE_FILE
    global dQueues
    global oSynchroPrint

    oParser = optparse.OptionParser(usage='usage: %prog [options]', version='%prog ' + __date__)
    oParser.add_option('-a', '--archivedirectoryprefix', default='vs-archive', help='prefix of the archive directory name (default vs-archive)')
    oParser.add_option('-f', '--ftpdirectory', default='', help='ftp directory name')
    oParser.add_option('-i', '--interval', type='int', default=60, help='interval between requests in seconds (default 60s)')
    (options, args) = oParser.parse_args()

    if len(args) != 0:
        oParser.print_help()
        print ''
        print '  Tool to log archive video surveillance pictures'
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'

    else:
        oSynchroPrint = cSynchroPrint()
        pictures = []
        for pic in Config2List(VS_CONFIG):
            if len(pic) == 4:
                pictures.append(cPictureData(pic[0], pic[1], pic[2], pic[3]))
            else:
                pictures.append(cPictureData(pic[0], pic[1], pic[2], pic[3], pic[4]))
        picturesSaved = DeSerialize()
        if picturesSaved != None:
            print 'Loaded %s' % PICKLE_FILE
            for oPictureSaved in picturesSaved:
                for oPicture in pictures:
                    if oPictureSaved.name == oPicture.name:
                        oPicture.crc32 = oPictureSaved.crc32
        dQueues = {}
        CreateQueueAndDaemons(pictures)

        ConfigureUrllib2()

        try:
            oSched = sched.scheduler(time.time, time.sleep)
            oSched.enter(options.interval, 1, ProcessPictures, [oSched, options.interval, pictures, options.archivedirectoryprefix, options.ftpdirectory])
            oSched.run()
        except KeyboardInterrupt:
            print 'Interrupted by user'
            for oPicture in pictures:
                oPicture.queue = None
            if not Serialize(pictures):
                print 'Serialization failed'

if __name__ == '__main__':
    Main()
