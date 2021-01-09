#!/usr/bin/env python

__description__ = 're extra'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2020/12/28'

"""

History:
  2014/04/04: refactoring from proxy-snort.py
  2017/05/17: 0.0.2 added extra=P
  2017/06/13: 0.0.3 added Script and Execute
  2018/07/15: 0.0.4 made decode_base58 more robust
  2020/12/08: 0.0.5 added DomainTLDValidate
  2020/12/28: Python 3

Todo:
"""

import re
import pickle
import math
import os
import glob
import datetime
import hashlib

def File2Strings(filename, comment=None):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return [line for line in map(lambda line:line.rstrip('\n'), f.readlines()) if comment == None or not line.startswith(comment)]
    except:
        return None
    finally:
        f.close()

def P23Chr(value):
    if type(value) == int:
        return chr(value)
    else:
        return value

def GFile2Strings(argument):
    if isinstance(argument, str):
        try:
            f = open(argument, 'r')
        except:
            return
    else:
        f = argument
    try:
        for line in f.readlines():
            yield line.rstrip('\n')
    except:
        return
    finally:
        if isinstance(argument, str):
            f.close()

def File2StringsFiltered(filename):
    """\
    Read a text file and return a list of strings,
    excluding comments and temporary lines.

    Returns None when an error occured.
    Comment lines (first character #) are not included in the returned
    list of strings.
    Temporary lines can be excluded from the returned list of strings,
    depending on the current date.
    Temporary lines are preceeded by a comment with this syntax:
        #begin:YYYY-MM-DD
        #begin:YYYY-MM-DD+##
        #end:YYYY-MM-DD
        #end:YYYY-MM-DD+##
        #within:YYYY-MM-DD~YYYY-MM-DD
    Temporary lines preceeded by #begin are included if the current date
    is equal or later than the date YYYY-MM-DD or the date YYYY-MM-DD
    + ## number of days
    Temporary lines preceeded by #end are included if the current date
    is equal or earlier than the date YYYY-MM-DD or the date YYYY-MM-DD
    + ## number of days
    Temporary lines preceeded by #within are included if the current date
    falls within the dates YYYY-MM-DD
    """

    commentCharacter = '#'
    try:
        f = open(filename, 'r')
    except:
        return None
    result = []
    try:
        skip = False
        for line in map(lambda line:line.rstrip('\n'), f.readlines()):
            if not skip and not line.startswith(commentCharacter):
                result.append(line)
            elif line.startswith(commentCharacter):
                oMatchBeginEnd = re.match(r'(begin|end):(\d{4})-(\d{2})-(\d{2})(\+\d+)?', line[1:], re.IGNORECASE)
                oMatchWithin = re.match(r'within:(\d{4})-(\d{2})-(\d{2})~(\d{4})-(\d{2})-(\d{2})', line[1:], re.IGNORECASE)
                if oMatchBeginEnd:
                    oDate = datetime.date(int(oMatchBeginEnd.group(2)), int(oMatchBeginEnd.group(3)), int(oMatchBeginEnd.group(4)))
                    if oMatchBeginEnd.group(5) != None:
                        oDate += datetime.timedelta(int(oMatchBeginEnd.group(5)[1:]))
                    if oMatchBeginEnd.group(1) == 'begin' and oDate > datetime.date.today():
                        skip = True
                    if oMatchBeginEnd.group(1) == 'end' and oDate < datetime.date.today():
                        skip = True
                elif oMatchWithin:
                    oDateBegin = datetime.date(int(oMatchWithin.group(1)), int(oMatchWithin.group(2)), int(oMatchWithin.group(3)))
                    oDateEnd = datetime.date(int(oMatchWithin.group(4)), int(oMatchWithin.group(5)), int(oMatchWithin.group(6)))
                    if oDateBegin > datetime.date.today() or oDateEnd < datetime.date.today():
                        skip = True
            elif skip:
                skip = False
    except:
        return None
    finally:
        f.close()
    return result

def decode_base58(bc, length):
    digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = 0
    for char in bc:
        if not char in digits58:
            return None
        n = n * 58 + digits58.index(char)
#    print(n.to_bytes(length, 'big'))
#    return n.to_bytes(length, 'big')
    return ''.join([chr((n >> i*8) & 0xff) for i in reversed(range(length))])

def BTCValidate(bc):
    bcbytes = decode_base58(bc, 25)
    if bcbytes == None:
        return False
    return bcbytes[-4:] == hashlib.sha256(hashlib.sha256(bcbytes[:-4]).digest()).digest()[:4]

tlds = [
    '.aaa',
    '.aarp',
    '.abarth',
    '.abb',
    '.abbott',
    '.abbvie',
    '.abc',
    '.able',
    '.abogado',
    '.abudhabi',
    '.ac',
    '.academy',
    '.accenture',
    '.accountant',
    '.accountants',
    '.aco',
    '.active',
    '.actor',
    '.ad',
    '.adac',
    '.ads',
    '.adult',
    '.ae',
    '.aeg',
    '.aero',
    '.aetna',
    '.af',
    '.afamilycompany',
    '.afl',
    '.africa',
    '.ag',
    '.agakhan',
    '.agency',
    '.ai',
    '.aig',
    '.aigo',
    '.airbus',
    '.airforce',
    '.airtel',
    '.akdn',
    '.al',
    '.alfaromeo',
    '.alibaba',
    '.alipay',
    '.allfinanz',
    '.allstate',
    '.ally',
    '.alsace',
    '.alstom',
    '.am',
    '.amazon',
    '.americanexpress',
    '.americanfamily',
    '.amex',
    '.amfam',
    '.amica',
    '.amsterdam',
    '.an',
    '.analytics',
    '.android',
    '.anquan',
    '.anz',
    '.ao',
    '.aol',
    '.apartments',
    '.app',
    '.apple',
    '.aq',
    '.aquarelle',
    '.ar',
    '.arab',
    '.aramco',
    '.archi',
    '.army',
    '.arpa',
    '.art',
    '.arte',
    '.as',
    '.asda',
    '.asia',
    '.associates',
    '.at',
    '.athleta',
    '.attorney',
    '.au',
    '.auction',
    '.audi',
    '.audible',
    '.audio',
    '.auspost',
    '.author',
    '.auto',
    '.autos',
    '.avianca',
    '.aw',
    '.aws',
    '.ax',
    '.axa',
    '.az',
    '.azure',
    '.ba',
    '.baby',
    '.baidu',
    '.banamex',
    '.bananarepublic',
    '.band',
    '.bank',
    '.bar',
    '.barcelona',
    '.barclaycard',
    '.barclays',
    '.barefoot',
    '.bargains',
    '.baseball',
    '.basketball',
    '.bauhaus',
    '.bayern',
    '.bb',
    '.bbc',
    '.bbt',
    '.bbva',
    '.bcg',
    '.bcn',
    '.bd',
    '.be',
    '.beats',
    '.beauty',
    '.beer',
    '.bentley',
    '.berlin',
    '.best',
    '.bestbuy',
    '.bet',
    '.bf',
    '.bg',
    '.bh',
    '.bharti',
    '.bi',
    '.bible',
    '.bid',
    '.bike',
    '.bing',
    '.bingo',
    '.bio',
    '.biz',
    '.bj',
    '.bl',
    '.black',
    '.blackfriday',
    '.blanco',
    '.blockbuster',
    '.blog',
    '.bloomberg',
    '.blue',
    '.bm',
    '.bms',
    '.bmw',
    '.bn',
    '.bnl',
    '.bnpparibas',
    '.bo',
    '.boats',
    '.boehringer',
    '.bofa',
    '.bom',
    '.bond',
    '.boo',
    '.book',
    '.booking',
    '.boots',
    '.bosch',
    '.bostik',
    '.boston',
    '.bot',
    '.boutique',
    '.box',
    '.bq',
    '.br',
    '.bradesco',
    '.bridgestone',
    '.broadway',
    '.broker',
    '.brother',
    '.brussels',
    '.bs',
    '.bt',
    '.budapest',
    '.bugatti',
    '.build',
    '.builders',
    '.business',
    '.buy',
    '.buzz',
    '.bv',
    '.bw',
    '.by',
    '.bz',
    '.bzh',
    '.ca',
    '.cab',
    '.cafe',
    '.cal',
    '.call',
    '.calvinklein',
    '.cam',
    '.camera',
    '.camp',
    '.cancerresearch',
    '.canon',
    '.capetown',
    '.capital',
    '.capitalone',
    '.car',
    '.caravan',
    '.cards',
    '.care',
    '.career',
    '.careers',
    '.cars',
    '.cartier',
    '.casa',
    '.case',
    '.caseih',
    '.cash',
    '.casino',
    '.cat',
    '.catering',
    '.catholic',
    '.cba',
    '.cbn',
    '.cbre',
    '.cbs',
    '.cc',
    '.cd',
    '.ceb',
    '.center',
    '.ceo',
    '.cern',
    '.cf',
    '.cfa',
    '.cfd',
    '.cg',
    '.ch',
    '.chanel',
    '.channel',
    '.charity',
    '.chase',
    '.chat',
    '.cheap',
    '.chintai',
    '.chloe',
    '.christmas',
    '.chrome',
    '.chrysler',
    '.church',
    '.ci',
    '.cipriani',
    '.circle',
    '.cisco',
    '.citadel',
    '.citi',
    '.citic',
    '.city',
    '.cityeats',
    '.ck',
    '.cl',
    '.claims',
    '.cleaning',
    '.click',
    '.clinic',
    '.clinique',
    '.clothing',
    '.cloud',
    '.club',
    '.clubmed',
    '.cm',
    '.cn',
    '.co',
    '.coach',
    '.codes',
    '.coffee',
    '.college',
    '.cologne',
    '.com',
    '.comcast',
    '.commbank',
    '.community',
    '.company',
    '.compare',
    '.computer',
    '.comsec',
    '.condos',
    '.construction',
    '.consulting',
    '.contact',
    '.contractors',
    '.cooking',
    '.cookingchannel',
    '.cool',
    '.coop',
    '.corsica',
    '.country',
    '.coupon',
    '.coupons',
    '.courses',
    '.cpa',
    '.cr',
    '.credit',
    '.creditcard',
    '.creditunion',
    '.cricket',
    '.crown',
    '.crs',
    '.cruise',
    '.cruises',
    '.csc',
    '.cu',
    '.cuisinella',
    '.cv',
    '.cw',
    '.cx',
    '.cy',
    '.cymru',
    '.cyou',
    '.cz',
    '.dabur',
    '.dad',
    '.dance',
    '.data',
    '.date',
    '.dating',
    '.datsun',
    '.day',
    '.dclk',
    '.dds',
    '.de',
    '.deal',
    '.dealer',
    '.deals',
    '.degree',
    '.delivery',
    '.dell',
    '.deloitte',
    '.delta',
    '.democrat',
    '.dental',
    '.dentist',
    '.desi',
    '.design',
    '.dev',
    '.dhl',
    '.diamonds',
    '.diet',
    '.digital',
    '.direct',
    '.directory',
    '.discount',
    '.discover',
    '.dish',
    '.diy',
    '.dj',
    '.dk',
    '.dm',
    '.dnp',
    '.do',
    '.docs',
    '.doctor',
    '.dodge',
    '.dog',
    '.doha',
    '.domains',
    '.doosan',
    '.dot',
    '.download',
    '.drive',
    '.dtv',
    '.dubai',
    '.duck',
    '.dunlop',
    '.duns',
    '.dupont',
    '.durban',
    '.dvag',
    '.dvr',
    '.dz',
    '.earth',
    '.eat',
    '.ec',
    '.eco',
    '.edeka',
    '.edu',
    '.education',
    '.ee',
    '.eg',
    '.eh',
    '.email',
    '.emerck',
    '.energy',
    '.engineer',
    '.engineering',
    '.enterprises',
    '.epost',
    '.epson',
    '.equipment',
    '.er',
    '.ericsson',
    '.erni',
    '.es',
    '.esq',
    '.estate',
    '.esurance',
    '.et',
    '.etisalat',
    '.eu',
    '.eurovision',
    '.eus',
    '.events',
    '.everbank',
    '.exchange',
    '.expert',
    '.exposed',
    '.express',
    '.extraspace',
    '.fage',
    '.fail',
    '.fairwinds',
    '.faith',
    '.family',
    '.fan',
    '.fans',
    '.farm',
    '.farmers',
    '.fashion',
    '.fast',
    '.fedex',
    '.feedback',
    '.ferrari',
    '.ferrero',
    '.fi',
    '.fiat',
    '.fidelity',
    '.fido',
    '.film',
    '.final',
    '.finance',
    '.financial',
    '.fire',
    '.firestone',
    '.firmdale',
    '.fish',
    '.fishing',
    '.fit',
    '.fitness',
    '.fj',
    '.fk',
    '.flickr',
    '.flights',
    '.flir',
    '.florist',
    '.flowers',
    '.flsmidth',
    '.fly',
    '.fm',
    '.fo',
    '.foo',
    '.food',
    '.foodnetwork',
    '.football',
    '.ford',
    '.forex',
    '.forsale',
    '.forum',
    '.foundation',
    '.fox',
    '.fr',
    '.free',
    '.fresenius',
    '.frl',
    '.frogans',
    '.frontdoor',
    '.frontier',
    '.ftr',
    '.fujitsu',
    '.fujixerox',
    '.fun',
    '.fund',
    '.furniture',
    '.futbol',
    '.fyi',
    '.ga',
    '.gal',
    '.gallery',
    '.gallo',
    '.gallup',
    '.game',
    '.games',
    '.gap',
    '.garden',
    '.gay',
    '.gb',
    '.gbiz',
    '.gd',
    '.gdn',
    '.ge',
    '.gea',
    '.gent',
    '.genting',
    '.george',
    '.gf',
    '.gg',
    '.ggee',
    '.gh',
    '.gi',
    '.gift',
    '.gifts',
    '.gives',
    '.giving',
    '.gl',
    '.glade',
    '.glass',
    '.gle',
    '.global',
    '.globo',
    '.gm',
    '.gmail',
    '.gmbh',
    '.gmo',
    '.gmx',
    '.gn',
    '.godaddy',
    '.gold',
    '.goldpoint',
    '.golf',
    '.goo',
    '.goodhands',
    '.goodyear',
    '.goog',
    '.google',
    '.gop',
    '.got',
    '.gov',
    '.gp',
    '.gq',
    '.gr',
    '.grainger',
    '.graphics',
    '.gratis',
    '.green',
    '.gripe',
    '.grocery',
    '.group',
    '.gs',
    '.gt',
    '.gu',
    '.guardian',
    '.gucci',
    '.guge',
    '.guide',
    '.guitars',
    '.guru',
    '.gw',
    '.gy',
    '.hair',
    '.hamburg',
    '.hangout',
    '.haus',
    '.hbo',
    '.hdfc',
    '.hdfcbank',
    '.health',
    '.healthcare',
    '.help',
    '.helsinki',
    '.here',
    '.hermes',
    '.hgtv',
    '.hiphop',
    '.hisamitsu',
    '.hitachi',
    '.hiv',
    '.hk',
    '.hkt',
    '.hm',
    '.hn',
    '.hockey',
    '.holdings',
    '.holiday',
    '.homedepot',
    '.homegoods',
    '.homes',
    '.homesense',
    '.honda',
    '.honeywell',
    '.horse',
    '.hospital',
    '.host',
    '.hosting',
    '.hot',
    '.hoteles',
    '.hotels',
    '.hotmail',
    '.house',
    '.how',
    '.hr',
    '.hsbc',
    '.ht',
    '.htc',
    '.hu',
    '.hughes',
    '.hyatt',
    '.hyundai',
    '.ibm',
    '.icbc',
    '.ice',
    '.icu',
    '.id',
    '.ie',
    '.ieee',
    '.ifm',
    '.iinet',
    '.ikano',
    '.il',
    '.im',
    '.imamat',
    '.imdb',
    '.immo',
    '.immobilien',
    '.in',
    '.inc',
    '.industries',
    '.infiniti',
    '.info',
    '.ing',
    '.ink',
    '.institute',
    '.insurance',
    '.insure',
    '.int',
    '.intel',
    '.international',
    '.intuit',
    '.investments',
    '.io',
    '.ipiranga',
    '.iq',
    '.ir',
    '.irish',
    '.is',
    '.iselect',
    '.ismaili',
    '.ist',
    '.istanbul',
    '.it',
    '.itau',
    '.itv',
    '.iveco',
    '.iwc',
    '.jaguar',
    '.java',
    '.jcb',
    '.jcp',
    '.je',
    '.jeep',
    '.jetzt',
    '.jewelry',
    '.jio',
    '.jlc',
    '.jll',
    '.jm',
    '.jmp',
    '.jnj',
    '.jo',
    '.jobs',
    '.joburg',
    '.jot',
    '.joy',
    '.jp',
    '.jpmorgan',
    '.jprs',
    '.juegos',
    '.juniper',
    '.kaufen',
    '.kddi',
    '.ke',
    '.kerryhotels',
    '.kerrylogistics',
    '.kerryproperties',
    '.kfh',
    '.kg',
    '.kh',
    '.ki',
    '.kia',
    '.kim',
    '.kinder',
    '.kindle',
    '.kitchen',
    '.kiwi',
    '.km',
    '.kn',
    '.koeln',
    '.komatsu',
    '.kosher',
    '.kp',
    '.kpmg',
    '.kpn',
    '.kr',
    '.krd',
    '.kred',
    '.kuokgroup',
    '.kw',
    '.ky',
    '.kyoto',
    '.kz',
    '.la',
    '.lacaixa',
    '.ladbrokes',
    '.lamborghini',
    '.lamer',
    '.lancaster',
    '.lancia',
    '.lancome',
    '.land',
    '.landrover',
    '.lanxess',
    '.lasalle',
    '.lat',
    '.latino',
    '.latrobe',
    '.law',
    '.lawyer',
    '.lb',
    '.lc',
    '.lds',
    '.lease',
    '.leclerc',
    '.lefrak',
    '.legal',
    '.lego',
    '.lexus',
    '.lgbt',
    '.li',
    '.liaison',
    '.lidl',
    '.life',
    '.lifeinsurance',
    '.lifestyle',
    '.lighting',
    '.like',
    '.lilly',
    '.limited',
    '.limo',
    '.lincoln',
    '.linde',
    '.link',
    '.lipsy',
    '.live',
    '.living',
    '.lixil',
    '.lk',
    '.llc',
    '.llp',
    '.loan',
    '.loans',
    '.locker',
    '.locus',
    '.loft',
    '.lol',
    '.london',
    '.lotte',
    '.lotto',
    '.love',
    '.lpl',
    '.lplfinancial',
    '.lr',
    '.ls',
    '.lt',
    '.ltd',
    '.ltda',
    '.lu',
    '.lundbeck',
    '.lupin',
    '.luxe',
    '.luxury',
    '.lv',
    '.ly',
    '.ma',
    '.macys',
    '.madrid',
    '.maif',
    '.maison',
    '.makeup',
    '.man',
    '.management',
    '.mango',
    '.map',
    '.market',
    '.marketing',
    '.markets',
    '.marriott',
    '.marshalls',
    '.maserati',
    '.mattel',
    '.mba',
    '.mc',
    '.mcd',
    '.mcdonalds',
    '.mckinsey',
    '.md',
    '.me',
    '.med',
    '.media',
    '.meet',
    '.melbourne',
    '.meme',
    '.memorial',
    '.men',
    '.menu',
    '.meo',
    '.merckmsd',
    '.metlife',
    '.mf',
    '.mg',
    '.mh',
    '.miami',
    '.microsoft',
    '.mil',
    '.mini',
    '.mint',
    '.mit',
    '.mitsubishi',
    '.mk',
    '.ml',
    '.mlb',
    '.mls',
    '.mm',
    '.mma',
    '.mn',
    '.mo',
    '.mobi',
    '.mobile',
    '.mobily',
    '.moda',
    '.moe',
    '.moi',
    '.mom',
    '.monash',
    '.money',
    '.monster',
    '.montblanc',
    '.mopar',
    '.mormon',
    '.mortgage',
    '.moscow',
    '.moto',
    '.motorcycles',
    '.mov',
    '.movie',
    '.movistar',
    '.mp',
    '.mq',
    '.mr',
    '.ms',
    '.msd',
    '.mt',
    '.mtn',
    '.mtpc',
    '.mtr',
    '.mu',
    '.museum',
    '.mutual',
    '.mutuelle',
    '.mv',
    '.mw',
    '.mx',
    '.my',
    '.mz',
    '.na',
    '.nab',
    '.nadex',
    '.nagoya',
    '.name',
    '.nationwide',
    '.natura',
    '.navy',
    '.nba',
    '.nc',
    '.ne',
    '.nec',
    '.net',
    '.netbank',
    '.netflix',
    '.network',
    '.neustar',
    '.new',
    '.newholland',
    '.news',
    '.next',
    '.nextdirect',
    '.nexus',
    '.nf',
    '.nfl',
    '.ng',
    '.ngo',
    '.nhk',
    '.ni',
    '.nico',
    '.nike',
    '.nikon',
    '.ninja',
    '.nissan',
    '.nissay',
    '.nl',
    '.no',
    '.nokia',
    '.northwesternmutual',
    '.norton',
    '.now',
    '.nowruz',
    '.nowtv',
    '.np',
    '.nr',
    '.nra',
    '.nrw',
    '.ntt',
    '.nu',
    '.nyc',
    '.nz',
    '.obi',
    '.observer',
    '.off',
    '.office',
    '.okinawa',
    '.olayan',
    '.olayangroup',
    '.oldnavy',
    '.ollo',
    '.om',
    '.omega',
    '.one',
    '.ong',
    '.onl',
    '.online',
    '.onyourside',
    '.ooo',
    '.open',
    '.oracle',
    '.orange',
    '.org',
    '.organic',
    '.orientexpress',
    '.origins',
    '.osaka',
    '.otsuka',
    '.ott',
    '.ovh',
    '.pa',
    '.page',
    '.pamperedchef',
    '.panasonic',
    '.panerai',
    '.paris',
    '.pars',
    '.partners',
    '.parts',
    '.party',
    '.passagens',
    '.pay',
    '.pccw',
    '.pe',
    '.pet',
    '.pf',
    '.pfizer',
    '.pg',
    '.ph',
    '.pharmacy',
    '.phd',
    '.philips',
    '.phone',
    '.photo',
    '.photography',
    '.photos',
    '.physio',
    '.piaget',
    '.pics',
    '.pictet',
    '.pictures',
    '.pid',
    '.pin',
    '.ping',
    '.pink',
    '.pioneer',
    '.pizza',
    '.pk',
    '.pl',
    '.place',
    '.play',
    '.playstation',
    '.plumbing',
    '.plus',
    '.pm',
    '.pn',
    '.pnc',
    '.pohl',
    '.poker',
    '.politie',
    '.porn',
    '.post',
    '.pr',
    '.pramerica',
    '.praxi',
    '.press',
    '.prime',
    '.pro',
    '.prod',
    '.productions',
    '.prof',
    '.progressive',
    '.promo',
    '.properties',
    '.property',
    '.protection',
    '.pru',
    '.prudential',
    '.ps',
    '.pt',
    '.pub',
    '.pw',
    '.pwc',
    '.py',
    '.qa',
    '.qpon',
    '.quebec',
    '.quest',
    '.qvc',
    '.racing',
    '.radio',
    '.raid',
    '.re',
    '.read',
    '.realestate',
    '.realtor',
    '.realty',
    '.recipes',
    '.red',
    '.redstone',
    '.redumbrella',
    '.rehab',
    '.reise',
    '.reisen',
    '.reit',
    '.reliance',
    '.ren',
    '.rent',
    '.rentals',
    '.repair',
    '.report',
    '.republican',
    '.rest',
    '.restaurant',
    '.review',
    '.reviews',
    '.rexroth',
    '.rich',
    '.richardli',
    '.ricoh',
    '.rightathome',
    '.ril',
    '.rio',
    '.rip',
    '.rmit',
    '.ro',
    '.rocher',
    '.rocks',
    '.rodeo',
    '.rogers',
    '.room',
    '.rs',
    '.rsvp',
    '.ru',
    '.rugby',
    '.ruhr',
    '.run',
    '.rw',
    '.rwe',
    '.ryukyu',
    '.sa',
    '.saarland',
    '.safe',
    '.safety',
    '.sakura',
    '.sale',
    '.salon',
    '.samsclub',
    '.samsung',
    '.sandvik',
    '.sandvikcoromant',
    '.sanofi',
    '.sap',
    '.sapo',
    '.sarl',
    '.sas',
    '.save',
    '.saxo',
    '.sb',
    '.sbi',
    '.sbs',
    '.sc',
    '.sca',
    '.scb',
    '.schaeffler',
    '.schmidt',
    '.scholarships',
    '.school',
    '.schule',
    '.schwarz',
    '.science',
    '.scjohnson',
    '.scor',
    '.scot',
    '.sd',
    '.se',
    '.search',
    '.seat',
    '.secure',
    '.security',
    '.seek',
    '.select',
    '.sener',
    '.services',
    '.ses',
    '.seven',
    '.sew',
    '.sex',
    '.sexy',
    '.sfr',
    '.sg',
    '.sh',
    '.shangrila',
    '.sharp',
    '.shaw',
    '.shell',
    '.shia',
    '.shiksha',
    '.shoes',
    '.shop',
    '.shopping',
    '.shouji',
    '.show',
    '.showtime',
    '.shriram',
    '.si',
    '.silk',
    '.sina',
    '.singles',
    '.site',
    '.sj',
    '.sk',
    '.ski',
    '.skin',
    '.sky',
    '.skype',
    '.sl',
    '.sling',
    '.sm',
    '.smart',
    '.smile',
    '.sn',
    '.sncf',
    '.so',
    '.soccer',
    '.social',
    '.softbank',
    '.software',
    '.sohu',
    '.solar',
    '.solutions',
    '.song',
    '.sony',
    '.soy',
    '.spa',
    '.space',
    '.spiegel',
    '.sport',
    '.spot',
    '.spreadbetting',
    '.sr',
    '.srl',
    '.srt',
    '.ss',
    '.st',
    '.stada',
    '.staples',
    '.star',
    '.starhub',
    '.statebank',
    '.statefarm',
    '.statoil',
    '.stc',
    '.stcgroup',
    '.stockholm',
    '.storage',
    '.store',
    '.stream',
    '.studio',
    '.study',
    '.style',
    '.su',
    '.sucks',
    '.supplies',
    '.supply',
    '.support',
    '.surf',
    '.surgery',
    '.suzuki',
    '.sv',
    '.swatch',
    '.swiftcover',
    '.swiss',
    '.sx',
    '.sy',
    '.sydney',
    '.symantec',
    '.systems',
    '.sz',
    '.tab',
    '.taipei',
    '.talk',
    '.taobao',
    '.target',
    '.tatamotors',
    '.tatar',
    '.tattoo',
    '.tax',
    '.taxi',
    '.tc',
    '.tci',
    '.td',
    '.tdk',
    '.team',
    '.tech',
    '.technology',
    '.tel',
    '.telecity',
    '.telefonica',
    '.temasek',
    '.tennis',
    '.teva',
    '.tf',
    '.tg',
    '.th',
    '.thd',
    '.theater',
    '.theatre',
    '.tiaa',
    '.tickets',
    '.tienda',
    '.tiffany',
    '.tips',
    '.tires',
    '.tirol',
    '.tj',
    '.tjmaxx',
    '.tjx',
    '.tk',
    '.tkmaxx',
    '.tl',
    '.tm',
    '.tmall',
    '.tn',
    '.to',
    '.today',
    '.tokyo',
    '.tools',
    '.top',
    '.toray',
    '.toshiba',
    '.total',
    '.tours',
    '.town',
    '.toyota',
    '.toys',
    '.tp',
    '.tr',
    '.trade',
    '.trading',
    '.training',
    '.travel',
    '.travelchannel',
    '.travelers',
    '.travelersinsurance',
    '.trust',
    '.trv',
    '.tt',
    '.tube',
    '.tui',
    '.tunes',
    '.tushu',
    '.tv',
    '.tvs',
    '.tw',
    '.tz',
    '.ua',
    '.ubank',
    '.ubs',
    '.uconnect',
    '.ug',
    '.uk',
    '.um',
    '.unicom',
    '.university',
    '.uno',
    '.uol',
    '.ups',
    '.us',
    '.uy',
    '.uz',
    '.va',
    '.vacations',
    '.vana',
    '.vanguard',
    '.vc',
    '.ve',
    '.vegas',
    '.ventures',
    '.verisign',
    '.versicherung',
    '.vet',
    '.vg',
    '.vi',
    '.viajes',
    '.video',
    '.vig',
    '.viking',
    '.villas',
    '.vin',
    '.vip',
    '.virgin',
    '.visa',
    '.vision',
    '.vista',
    '.vistaprint',
    '.viva',
    '.vivo',
    '.vlaanderen',
    '.vn',
    '.vodka',
    '.volkswagen',
    '.volvo',
    '.vote',
    '.voting',
    '.voto',
    '.voyage',
    '.vu',
    '.vuelos',
    '.wales',
    '.walmart',
    '.walter',
    '.wang',
    '.wanggou',
    '.warman',
    '.watch',
    '.watches',
    '.weather',
    '.weatherchannel',
    '.webcam',
    '.weber',
    '.website',
    '.wed',
    '.wedding',
    '.weibo',
    '.weir',
    '.wf',
    '.whoswho',
    '.wien',
    '.wiki',
    '.williamhill',
    '.win',
    '.windows',
    '.wine',
    '.winners',
    '.wme',
    '.wolterskluwer',
    '.woodside',
    '.work',
    '.works',
    '.world',
    '.wow',
    '.ws',
    '.wtc',
    '.wtf',
    '.xbox',
    '.xerox',
    '.xfinity',
    '.xihuan',
    '.xin',
    '.xperia',
    '.xxx',
    '.xyz',
    '.yachts',
    '.yahoo',
    '.yamaxun',
    '.yandex',
    '.ye',
    '.yodobashi',
    '.yoga',
    '.yokohama',
    '.you',
    '.youtube',
    '.yt',
    '.yun',
    '.za',
    '.zappos',
    '.zara',
    '.zero',
    '.zip',
    '.zippo',
    '.zm',
    '.zone',
    '.zuerich',
    '.zw',
]

def DomainTLDValidate(domain):
    if '..' in domain:
        return False
    tld = domain[domain.rfind('.'):]
    return tld in tlds

def CountUniques(data):
    dCount = {}
    for b in data:
        dCount[b] = True
    return len(dCount)

def Script(filename):
    execfile(filename, globals(), globals())

def Execute(pythoncode):
    exec(pythoncode, globals())

class cGibberishDetector():
    def __init__(self, filenamePickle='', acceptedCharacters='abcdefghijklmnopqrstuvwxyz '):
        self.filenamePickle = filenamePickle
        self.acceptedCharacters = acceptedCharacters
        self.ngramSize = 2
        self.pos = dict([(char, idx) for idx, char in enumerate(self.acceptedCharacters)])
        self.modelMatrix = None

    pickledata = b"""\
(dp0
S'acceptedCharacters'
p1
S'abcdefghijklmnopqrstuvwxyz '
p2
sS'modelProbabilityThreshold'
p3
F0.018782003473122023
sS'ngramSize'
p4
I2
sS'modelMatrix'
p5
(lp6
(lp7
F-8.569137312930899
aF-3.9369332597631863
aF-3.220670162697391
aF-3.0482479869676102
aF-6.052279063336297
aF-4.69956099775001
aF-3.9941585968087816
aF-6.710407217596661
aF-3.2453041060602184
aF-7.060740255010108
aF-4.512283359624297
aF-2.4997201529644935
aF-3.642636781640966
aF-1.5707462805725019
aF-7.978468801653891
aF-3.8936418102220776
aF-9.821900281426267
aF-2.3025283782801376
aF-2.348366425382398
aF-1.9448651421947813
aF-4.539158126663701
aF-3.871849760115083
aF-4.706359120463831
aF-6.560313338465017
aF-3.649725323207633
aF-6.641954302926283
aF-2.7134701747591117
aa(lp8
F-2.5528619980785
aF-5.139226208055755
aF-6.049719822245583
aF-6.219404795035026
aF-1.173596307609444
aF-8.563954087128105
aF-8.805116143944993
aF-8.494961215641153
aF-3.3328454702735173
aF-5.004532700251055
aF-8.805116143944993
aF-2.139085063222716
aF-6.121607051758899
aF-6.808562262070924
aF-2.1459387811703974
aF-8.312639658847198
aF-8.900426323749317
aF-2.719375008855968
aF-3.788438535392774
aF-4.703224376087508
aF-2.137350056136624
aF-6.320209494156992
aF-7.676650892127201
aF-8.900426323749317
aF-2.3611294272462486
aF-8.900426323749317
aF-4.738423113053401
aa(lp9
F-2.08946313988477
aF-9.398284978640158
aF-3.8466182187208457
aF-7.678499009037193
aF-1.7391136109740999
aF-8.792149175069843
aF-9.580606535434113
aF-1.9093388132314668
aF-2.9331775988939013
aF-9.485296355629789
aF-3.343650033348159
aF-3.276523430584318
aF-8.515895798441685
aF-8.838669190704735
aF-1.6000355228278762
aF-9.485296355629789
aF-6.386023403134956
aF-3.377666241879603
aF-5.838186314392146
aF-2.3909106346293085
aF-3.2184408726543063
aF-9.485296355629789
aF-8.838669190704735
aF-9.580606535434113
aF-4.621264535725407
aF-8.299672689972049
aF-3.8668737299247438
aa(lp10
F-3.7200475908408235
aF-7.418434550575756
aF-7.88681348409449
aF-4.564865474086475
aF-1.9699465394791131
aF-6.796896902393934
aF-5.430448837645974
aF-6.754155354016663
aF-2.4627220077183942
aF-6.277375571660389
aF-7.666270714480338
aF-4.558326450319418
aF-5.5188785108919935
aF-5.946484744877372
aF-3.117009722931763
aF-8.380471304238116
aF-8.136274343726074
aF-3.6243165394601604
aF-3.6811521539816408
aF-7.1936663035345445
aF-3.9941983786827824
aF-5.568764165402863
aF-7.077327311450395
aF-9.928033812954128
aF-4.613843097249801
aF-9.745712256160173
aF-0.5394468422260206
aa(lp11
F-3.0956911156796725
aF-6.3279563530093395
aF-3.711394117529345
aF-2.414309096615009
aF-3.7280101535107066
aF-4.555095809949321
aF-4.9582369569836615
aF-6.340824177620733
aF-4.465115884463944
aF-8.043262266521952
aF-7.012917948982845
aF-3.4395652463282116
aF-3.7489856294972617
aF-2.389153595060143
aF-5.281198278652138
aF-4.426598784036354
aF-6.265131628349503
aF-1.976271246918681
aF-2.519225987547763
aF-3.7331106440131854
aF-6.05129367580717
aF-4.115226028040922
aF-4.719249301196115
aF-4.451178867151557
aF-4.535588241035776
aF-7.731754615658102
aF-1.1291364595675442
aa(lp12
F-2.7634422911455703
aF-7.9114774546442685
aF-7.529542843946299
aF-8.494623739989885
aF-2.451100566435661
aF-2.926120215794328
aF-7.612234559791412
aF-8.53718335440868
aF-2.4505074466080714
aF-9.033620240722573
aF-8.72823859117139
aF-3.748243385450271
aF-8.839464226281615
aF-7.66534438510536
aF-1.9043799278633868
aF-8.305381740351358
aF-9.370092477343785
aF-2.3558173549839756
aF-5.929674382528349
aF-3.315653131074415
aF-3.5058932812816797
aF-9.370092477343785
aF-7.801476559429941
aF-9.370092477343785
aF-6.135343303319295
aF-9.370092477343785
aF-0.9976707550554195
aa(lp13
F-2.681117318742622
aF-8.560252680876685
aF-8.083328608786376
aF-6.8862762473050125
aF-1.9631827738890724
aF-7.924263914156688
aF-4.61975020412667
aF-2.2213641819441556
aF-2.8612966495974126
aF-9.148039345778804
aF-8.560252680876685
aF-3.35807917488155
aF-6.075346031088684
aF-3.7399711152716475
aF-2.831958278425978
aF-7.954116877306369
aF-9.052729165974478
aF-2.5526687518888194
aF-4.062915199691808
aF-4.943346726387837
aF-3.494498087559349
aF-9.148039345778804
aF-7.579423427864958
aF-9.148039345778804
aF-5.882279935011752
aF-8.617411094716633
aF-1.0302198528344138
aa(lp14
F-1.8949866865832032
aF-7.38720654177459
aF-8.05310407988716
aF-7.542278456121169
aF-0.7286353651447546
aF-7.858315754328075
aF-9.589971299486425
aF-8.779041083270096
aF-1.9951372153459488
aF-10.100796923252416
aF-7.885223207247999
aF-6.635061020452689
aF-6.261344610659105
aF-6.705170586639715
aF-2.5617698674284206
aF-9.253499062865211
aF-10.100796923252416
aF-4.5720294302077304
aF-6.222675469499951
aF-3.764561336708525
aF-4.622243506401445
aF-9.541181135316993
aF-7.3816968859636205
aF-10.28311848004637
aF-5.024581983510178
aF-10.187808300242045
aF-2.3623088007577695
aa(lp15
F-3.712244886548001
aF-4.717475282130211
aF-2.783984370515817
aF-3.2216013768067646
aF-3.1683365236496233
aF-3.90382545586124
aF-3.680790547058952
aF-9.119304544100272
aF-6.422989599216483
aF-10.323277348426208
aF-5.240838322200969
aF-3.0795261367137394
aF-3.173687619686372
aF-1.3126793991869439
aF-2.664381175855551
aF-4.9236074876178835
aF-7.895529112478156
aF-3.409705684122631
aF-2.051579832828198
aF-2.1011937452905483
aF-6.511074678280273
aF-3.8167461832949807
aF-9.672689782285058
aF-6.168308164387673
aF-10.410288725415837
aF-5.511770729440288
aF-3.788398987959084
aa(lp16
F-2.3427609160575655
aF-6.1024094410597085
aF-6.037870919922137
aF-6.507874549167873
aF-1.4153520955994334
aF-6.245510284700382
aF-6.17140231254666
aF-6.325552992373918
aF-5.51462277615759
aF-6.507874549167873
aF-6.245510284700382
aF-6.412564369363548
aF-6.325552992373918
aF-6.507874549167873
aF-1.2783714986201964
aF-6.412564369363548
aF-6.325552992373918
aF-6.1024094410597085
aF-6.1024094410597085
aF-6.245510284700382
aF-1.1002544477293865
aF-6.507874549167873
aF-6.245510284700382
aF-6.507874549167873
aF-6.507874549167873
aF-6.507874549167873
aF-4.859215923580492
aa(lp17
F-3.6194933584945135
aF-7.047703539402737
aF-6.062419936041631
aF-7.671857848475732
aF-1.2114318817004575
aF-6.285563487355841
aF-6.824559988088527
aF-3.6311485020862624
aF-1.7851984157338754
aF-7.814958692116405
aF-7.489536291681777
aF-3.88766821455747
aF-6.036102627724257
aF-2.3543916630889337
aF-3.8417682258102714
aF-7.546694705521725
aF-7.9820127767795706
aF-5.48206824962703
aF-3.0008999219496366
aF-6.6910285954640045
aF-3.73872587983735
aF-7.2444138336487915
aF-5.438265626968637
aF-8.077322956583895
aF-4.682814563072537
aF-8.077322956583895
aF-1.4288566755523215
aa(lp18
F-2.269183388314388
aF-6.573297799694782
aF-5.745479365449931
aF-2.8596367214634224
aF-1.7841347050080587
aF-4.144047900909572
aF-6.844091654118041
aF-7.7437746495925355
aF-2.175115871017978
aF-9.701519256294851
aF-4.956587127931601
aF-2.065933606191924
aF-5.060338632783727
aF-6.492693767280152
aF-2.4508837443961715
aF-5.604400767190025
aF-9.701519256294851
aF-5.648286082315182
aF-3.879460040714278
aF-3.864517937852428
aF-3.8209862698941515
aF-5.091361528795721
aF-5.466205750947557
aF-9.883840813088806
aF-2.333600268348952
aF-8.602906967626742
aF-2.0434097729831913
aa(lp19
F-1.7539942375247688
aF-3.6841198980845076
aF-6.559311098803656
aF-8.439623965373157
aF-1.3654444296574595
aF-6.4075846625879045
aF-9.337565558579115
aF-8.238953269911006
aF-2.4389427631602505
aF-9.17051147391595
aF-8.902247487321269
aF-6.206031743866062
aF-3.641082386404525
aF-5.662416297277081
aF-2.2280575251437695
aF-2.6972144960398214
aF-9.432875738383439
aF-5.501050105659114
aF-3.5381974599631496
aF-6.907147094075184
aF-3.4685254837670296
aF-9.250554181589486
aF-8.071899185247839
aF-9.432875738383439
aF-3.424799925470261
aF-9.432875738383439
aF-1.8968318511898539
aa(lp20
F-3.41157713428474
aF-6.728285208389976
aF-3.0909427430720093
aF-1.740264825689735
aF-2.5015190512398306
aF-4.817371901371758
aF-2.113210530516431
aF-6.807749379744223
aF-3.295792549094097
aF-6.252798951069294
aF-4.917797884336954
aF-4.632769841879079
aF-5.98877585293416
aF-4.66665175664129
aF-2.876759518067293
aF-7.603753945743875
aF-6.864465609186075
aF-7.187239001449126
aF-3.052336215755031
aF-2.2647479268985964
aF-4.9001580949910455
aF-5.348959516586179
aF-7.14773655847288
aF-7.454376544669275
aF-4.546351845156791
aF-8.807726750069811
aF-1.4656789800236865
aa(lp21
F-5.082241389138844
aF-5.142393631993602
aF-4.276598353328924
aF-4.085216817689867
aF-5.759968385010914
aF-2.174773615995364
aF-5.288621572218711
aF-6.090174110360315
aF-4.4715723308194235
aF-6.90687468303798
aF-4.432658655412265
aF-3.2277431063139637
aF-2.8212923556513845
aF-1.7681088393713913
aF-3.5156224239092224
aF-3.9518016568316168
aF-8.986316224717816
aF-2.1664590794141954
aF-3.3712131841519417
aF-3.1224483347145418
aF-2.2101893882141153
aF-3.5450716407123704
aF-3.1404797504673136
aF-6.663111844521034
aF-5.51344438505264
aF-7.704225641127928
aF-2.2129736790077486
aa(lp22
F-2.136265349667144
aF-7.648749930275526
aF-6.522163789565011
aF-8.503165258431594
aF-1.734614577170007
aF-6.50168525822147
aF-7.785325465281278
aF-3.642577960578998
aF-2.654272848600284
aF-8.454375094262163
aF-7.861311372259199
aF-2.3851781986138283
aF-6.363099094935324
aF-7.294204912594619
aF-2.116201767527298
aF-2.7907534570773387
aF-9.196312438991539
aF-1.7868731941606955
aF-3.8487288311405847
aF-3.2942257030347744
aF-3.1971277688684197
aF-9.196312438991539
aF-7.0800569241889875
aF-9.196312438991539
aF-4.987152202340858
aF-9.196312438991539
aF-2.9363486388485507
aa(lp23
F-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-0.057170565024993084
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-6.182291496945648
aF-5.540437610773254
aa(lp24
F-2.5722807952437394
aF-5.99205725679638
aF-4.319316764551239
aF-3.7284294070555273
aF-1.4225483817556492
aF-5.357231686671419
aF-4.331760927128789
aF-6.033757985995324
aF-2.364541745819138
aF-9.405183209323809
aF-4.850464566831816
aF-4.673556599383159
aF-3.74500437214974
aF-3.916576116332641
aF-2.322164557359624
aF-5.413979406021222
aF-9.0405400957359
aF-3.636862213530037
aF-2.9016138569514562
aF-3.2345687965875074
aF-3.9816438780223904
aF-4.905818082232694
aF-6.257588586460572
aF-10.13915238440401
aF-3.2585970253485272
aF-8.070182142591468
aF-1.7281348556024396
aa(lp25
F-3.2090119684802527
aF-6.334899523154303
aF-4.093299064417374
aF-7.59203503906228
aF-2.1586345703035548
aF-6.182995193953419
aF-7.849503332917564
aF-2.915257814589145
aF-2.7754710419906368
aF-9.550291023939893
aF-4.551024457450397
aF-4.707131510786311
aF-4.589272322367449
aF-6.243245073400844
aF-2.968928515714967
aF-3.853927304671137
aF-7.00903143760076
aF-8.243133983378726
aF-2.8108514947509753
aF-2.1177557637833035
aF-3.256550330868065
aF-7.865503674264006
aF-5.380597024476005
aF-10.383200146874996
aF-5.201416596582911
aF-9.913196517629261
aF-0.9911300598753203
aa(lp26
F-3.1682706209020797
aF-8.217706195099385
aF-5.878899838671022
aF-9.525219678366163
aF-2.3388918749787213
aF-7.172402459885784
aF-8.478432457562638
aF-1.1074718716074006
aF-2.3662341497302157
aF-10.456777882371107
aF-9.689522729657439
aF-4.418539855249544
aF-6.032391973858083
aF-7.21960886445558
aF-2.3367153961191565
aF-8.16191483547097
aF-10.719142146838596
aF-3.4624215669877803
aF-3.6797447588047447
aF-4.0251990917417855
aF-3.9002180815630756
aF-9.555991337032916
aF-5.18259559155831
aF-10.131355481936478
aF-4.204725796166784
aF-7.984774637419013
aF-1.5835253210583506
aa(lp27
F-3.6907063474960813
aF-3.7341336409281
aF-3.2454721262149633
aF-4.020608712629845
aF-3.281297978688059
aF-5.0172437658127595
aF-3.1933271849501734
aF-7.7963898885987
aF-3.73111886626001
aF-9.35453450664525
aF-6.208229374611885
aF-2.257675168572427
aF-3.4112977818505237
aF-2.089862646254399
aF-6.096437968623768
aF-3.100705695069777
aF-8.949069398537086
aF-1.905375903432984
aF-1.9722545836234537
aF-1.9648676140617645
aF-9.274491798971713
aF-6.7831953510849425
aF-9.35453450664525
aF-7.31765257938421
aF-7.3735330377786665
aF-5.267158613739243
aF-3.2700350935700784
aa(lp28
F-2.4677551327310105
aF-8.46601472297182
aF-8.561324902776146
aF-7.868177722216201
aF-0.5192363285514866
aF-8.561324902776146
aF-8.298960638308655
aF-8.46601472297182
aF-1.7429474349452256
aF-8.46601472297182
aF-7.919471016603751
aF-5.443374996497906
aF-8.561324902776146
aF-4.566800675836256
aF-2.7892609207035393
aF-8.561324902776146
aF-8.561324902776146
aF-6.268790145635601
aF-4.407140340198028
aF-7.973538237874027
aF-6.289199017266808
aF-8.379003345982191
aF-8.030696651713976
aF-8.46601472297182
aF-5.258107929474194
aF-8.561324902776146
aF-3.1228109057348257
aa(lp29
F-1.596798460957614
aF-7.6001421705956735
aF-7.640964165115928
aF-5.344648685135478
aF-1.8921021056868312
aF-6.839336341561913
aF-8.110967794361665
aF-1.6228272590921338
aF-1.7628783045649916
aF-8.87310784640856
aF-7.001305669506969
aF-5.467159861987808
aF-8.179960665848615
aF-3.2183655671770013
aF-2.524218636471301
aF-8.293289351155618
aF-9.209580083029774
aF-4.57000847032435
aF-4.2425484264156506
aF-5.65423202154036
aF-7.560921457442392
aF-9.209580083029774
aF-7.307472556632853
aF-9.209580083029774
aF-6.877436187794184
aF-9.02725852623582
aF-2.172728230713227
aa(lp30
F-2.254780968033424
aF-6.898209866138606
aF-2.027603216646053
aF-6.492744758030441
aF-2.462642464536694
aF-5.833499129146177
aF-6.898209866138606
aF-4.310445830910898
aF-2.0731012597852527
aF-6.898209866138606
aF-6.898209866138606
aF-6.42820623689287
aF-6.715888309344651
aF-6.898209866138606
aF-4.4558628307694015
aF-1.4955324842663262
aF-6.3675816150764355
aF-4.636446767664815
aF-5.766807754647505
aF-1.8703897472882491
aF-4.37248122183035
aF-4.348764695213034
aF-6.802899686334281
aF-4.473407140420311
aF-5.175443268397502
aF-6.898209866138606
aF-2.5557039896270073
aa(lp31
F-3.872874353532438
aF-6.07983833755968
aF-5.605956228985375
aF-6.1495716755743555
aF-2.9181087352006836
aF-5.833140189836589
aF-6.998723104610883
aF-7.317176835729417
aF-3.8266394412494407
aF-8.857621876676566
aF-7.45070822835394
aF-4.745382824577915
aF-4.447858487031085
aF-5.448125692199715
aF-2.2255103117197566
aF-4.737230605516364
aF-9.03994343347052
aF-5.751541545953709
aF-3.132676045163294
aF-4.230201081753655
aF-7.038463433260397
aF-7.65364907235063
aF-6.230540738108023
aF-7.70494236673818
aF-8.16447469611662
aF-7.731610613820342
aF-0.3817890191036424
aa(lp32
F-2.531179599331457
aF-6.00314605188182
aF-5.907835872077495
aF-4.694813232231641
aF-0.9292230185496455
aF-5.907835872077495
aF-6.00314605188182
aF-3.199785670975285
aF-2.3395844057521735
aF-6.00314605188182
aF-5.666673815260607
aF-3.886890537079268
aF-4.0016660516716955
aF-5.009894278871537
aF-1.7362497244615696
aF-6.00314605188182
aF-6.00314605188182
aF-6.00314605188182
aF-5.820824495087865
aF-5.907835872077495
aF-3.1183453390351104
aF-5.666673815260607
aF-5.907835872077495
aF-6.00314605188182
aF-4.568061526592497
aF-3.7731316517226094
aF-3.1699327078256037
aa(lp33
F-2.154456318300654
aF-3.132028909232904
aF-3.204240273221435
aF-3.554775966080049
aF-3.8320798875631166
aF-3.2625149066892174
aF-4.1318426237305275
aF-2.7847122791384975
aF-2.7534204117779435
aF-5.68607428491371
aF-5.271518205104294
aF-3.779792629468334
aF-3.352468498262208
aF-3.8123859357235683
aF-2.644532475328425
aF-3.3676057306367433
aF-6.237872536056438
aF-3.6809218434868227
aF-2.7030074975159986
aF-1.86142386740762
aF-4.4723885304095425
aF-4.918696830481552
aF-2.8042850405884527
aF-7.783949528282384
aF-4.702039558487341
aF-8.486442571260568
aF-3.2910629924454486
aas.
"""

    def Normalize(self, line):
        """ Return only the subset of chars from acceptedCharacters.
        This helps keep the  model relatively small by ignoring punctuation,
        infrequenty symbols, etc. """
        return [P23Chr(c) for c in line.lower() if P23Chr(c) in self.acceptedCharacters]

    def Ngram(self, line):
        """ Return all ngramSize grams from line """
        for start in range(0, len(line) - self.ngramSize + 1):
            yield ''.join(line[start:start + self.ngramSize])

    def AverageTransitionProbability(self, line):
        """ Return the average transition prob from line through self.modelMatrix. """
        log_prob = 0.0
        transition_ct = 0
        for a, b in self.Ngram(self.Normalize(line)):
            log_prob += self.modelMatrix[self.pos[a]][self.pos[b]]
            transition_ct += 1
        # The exponentiation translates from log probs to probs.
        return math.exp(log_prob / (transition_ct or 1))

    def Train(self, filenameReferencetext, filenameSensical, filenameGibberish):
        """ Write a simple model as a pickle file """
        k = len(self.acceptedCharacters)
        # Assume we have seen 10 of each character pair.  This acts as a kind of
        # prior or smoothing factor.  This way, if we see a character transition
        # live that we've never observed in the past, we won't assume the entire
        # string has 0 probability.
        countsMatrix = [[10 for i in xrange(k)] for i in xrange(k)]

        # Count transitions from big text file, taken
        # from http://norvig.com/spell-correct.html
        countNgrams = 0
        dCharacters = {}
        for line in GFile2Strings(filenameReferencetext):
            for a, b in self.Ngram(self.Normalize(line)):
                countsMatrix[self.pos[a]][self.pos[b]] += 1
                countNgrams += 1
            for character in line.lower():
                if character in dCharacters:
                    dCharacters[character] += 1
                else:
                    dCharacters[character] = 1

        # Normalize the countsMatrix so that they become log probabilities.
        # We use log probabilities rather than straight probabilities to avoid
        # numeric underflow issues with long texts.
        # This contains a justification:
        # http://squarecog.wordpress.com/2009/01/10/dealing-with-underflow-in-joint-probability-calculations/
        self.modelMatrix = [[math.log(count / float(sum(row))) for count in row] for row in countsMatrix]

        # Find the probability of generating a few arbitrarily choosen sensical and gibberish phrases.
        probabilitiesSensical = [self.AverageTransitionProbability(line) for line in GFile2Strings(filenameSensical)]
        probabilitiesGibberish = [self.AverageTransitionProbability(line) for line in GFile2Strings(filenameGibberish)]

        # Assert that we actually are capable of detecting the junk.
        assert min(probabilitiesSensical) > max(probabilitiesGibberish)

        # And pick a threshold halfway between the worst good and best bad inputs.
        self.modelProbabilityThreshold = (min(probabilitiesSensical) + max(probabilitiesGibberish)) / 2
        pickle.dump({'modelMatrix': self.modelMatrix, 'modelProbabilityThreshold': self.modelProbabilityThreshold, 'ngramSize': self.ngramSize, 'acceptedCharacters':self.acceptedCharacters}, open(self.filenamePickle, 'wb'))

        print('Different characters in reference file: %d' % len(dCharacters))
        for items in sorted(dCharacters.iteritems(), key=operator.itemgetter(1)):
            print(' %s: %d' % items)
        print('Number of ngrams in reference file: %d' % countNgrams)
        print('Highest probability from gibberish file: %f' % max(probabilitiesGibberish))
        print('Lowest probability from sensical file:   %f' % min(probabilitiesSensical))
        print('Probability threshold:                   %f' % self.modelProbabilityThreshold)

    def LoadModel(self):
        if self.filenamePickle == '':
            model_data = pickle.loads(cGibberishDetector.pickledata)
        else:
            model_data = pickle.load(open(self.filenamePickle, 'rb'))
        self.modelMatrix = model_data['modelMatrix']
        self.modelProbabilityThreshold = model_data['modelProbabilityThreshold']
        self.ngramSize = model_data['ngramSize']
        self.acceptedCharacters = model_data['acceptedCharacters']
        self.pos = dict([(char, idx) for idx, char in enumerate(self.acceptedCharacters)])

    def Sensical(self, line):
        if self.modelMatrix == None:
            self.LoadModel()
        return self.AverageTransitionProbability(line) > self.modelProbabilityThreshold

class cExtraSensical():
    def __init__(self, sensical, sensicalPickle=''):
        self.sensical = sensical
        self.oGibberishDetector = cGibberishDetector(sensicalPickle)

    def Test(self, data):
        sensical = self.oGibberishDetector.Sensical(data)
        if self.sensical:
            return sensical
        else:
            return not sensical

class cExtraList():
    def __init__(self, include, identifyer, dLists):
       self.include = include
       if not identifyer in dLists:
           raise Exception('cExtraList identifyer not in lists')
       self.datalist = File2StringsFiltered(dLists[identifyer])

    def Test(self, data):
        found = data.lower() in self.datalist
        if self.include:
            return found
        else:
            return not found

class cExtraPython():
    def __init__(self, functionname):
       self.function = eval(functionname)

    def Test(self, data):
        return self.function(data)

class cREExtra():
    def __init__(self, regex, flags, sensicalPickle='', listsDirectory=''):
        self.regex = regex
        self.flags = flags
        self.listsDirectory = listsDirectory
        self.oRE = re.compile(self.regex, self.flags)
        self.extra = None
        self.conditions = []

        if not self.regex.startswith('(?#extra='):
            return
        iRightParanthesis = regex.find(')')
        if iRightParanthesis == -1:
            raise Exception('Error extra regex comment: 1')
        self.extra = regex[9:iRightParanthesis]
 
        dLists = {os.path.basename(filename):filename for filename in sum(map(glob.glob, [os.path.join(listsDirectory, '*')]), [])}
        for condition in self.extra.split(';'):
            if condition.startswith('S:'):
                if condition[2:] != 'g' and condition[2:] != 's':
                    raise Exception('Error extra regex comment: 3')
                self.conditions.append(cExtraSensical(condition[2:] == 's', sensicalPickle))
            elif condition.startswith('E:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 4')
                self.conditions.append(cExtraList(False, condition[2:], dLists))
            elif condition.startswith('I:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 5')
                self.conditions.append(cExtraList(True, condition[2:], dLists))
            elif condition.startswith('P:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 6')
                self.conditions.append(cExtraPython(condition[2:]))
            else:
                raise Exception('Error extra regex comment: 2')

    def Test(self, data):
        return all([oCondition.Test(data) for oCondition in self.conditions])

    def Findall(self, line):
        found = self.oRE.findall(line)
        results = []
        for result in found:
            if isinstance(result, str):
                if self.Test(result):
                    results.append(result)
            if isinstance(result, tuple):
                results.append(result)
        return results

    def Search(self, line, flags=0):
        oMatch = self.oRE.search(line, flags)
        if oMatch == None:
            return None
        if self.Test(oMatch.group(0)):
            return oMatch
        else:
            return None

