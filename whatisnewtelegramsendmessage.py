#!/usr/bin/env python

__description__ = 'telegram'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2024/03/04'

"""
History:
  2022/11/19: start
  2022/11/20: continue
  2024/03/04: 0.0.2 added option -i

"""

import optparse
import requests
import binascii
import datetime
import sys

def NowUTCISO():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def TelegramSendMessage(message, apiToken, chatID):
    try:
        print(requests.post(f'https://api.telegram.org/bot{apiToken}/sendMessage', json={'chat_id': chatID, 'text': message}))
    except Exception as e:
        print(e)
        return -1

    return 0

def WhatIsNewTelegramSendMessage(args, options):
    if options.base64:
        message = binascii.a2b_base64(args[0]).decode('latin')
    elif options.stdin != '':
        message = sys.stdin.read()
        if options.stdin != 'all':
            message = '\n'.join(message.split('\n')[:int(options.stdin)])
    else:
        message = args[0]
    if options.prefix != '':
        message = '%s: %s' % (options.prefix, message)
    if options.timestamp:
        message = '%s: %s' % (NowUTCISO(), message)
    return TelegramSendMessage(message, options.apitoken, options.chatid)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] message\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-a', '--apitoken', type=str, default='', help='API token')
    oParser.add_option('-c', '--chatid', type=str, default='', help='Chat ID')
    oParser.add_option('-b', '--base64', action='store_true', default=False, help='Message is BASE64 encoded')
    oParser.add_option('-i', '--stdin', type=str, default='', help='Read message from stdin ("all" or number of lines)')
    oParser.add_option('-t', '--timestamp', action='store_true', default=False, help='Timestamp the message')
    oParser.add_option('-p', '--prefix', type=str, default='', help='Message prefix')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 1

    if len(args) != 1 and not options.stdin:
        oParser.print_help()
        return 1

    return WhatIsNewTelegramSendMessage(args, options)

if __name__ == '__main__':
    sys.exit(Main())
