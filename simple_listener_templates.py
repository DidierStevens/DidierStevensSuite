FILECONTENTTOSERVE = ReadBinaryFile(dVariables.get('FILETOSERVE', ''))

dListeners = {
    'HTTPWELCOME':  {THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK',
                                         b'Date: %TIME_GMT_RFC2822%',
                                         b'Server: Apache',
                                         b'Last-Modified: Wed, 06 Jul 2016 17:51:03 GMT',
                                         b'ETag: "59652-cfd-edc33a50bfec6"',
                                         b'Accept-Ranges: bytes',
                                         b'Content-Length: %CONTENT_LENGTH%',
                                         b'Connection: close',
                                         b'Content-Type: text/html; charset=UTF-8',
                                         b'',
                                         b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">',
                                         b'<link rel="icon" type="image/png" href="favicon.png"/>',
                                         b'<html>',
                                         b'  <head>',
                                         b'    <title>Home</title>',
                                         b'    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">',
                                         b'  </head>',
                                         b'  <body>Welcome home!</body>',
                                         b'</html>'])},

    'HTTPSWELCOME': {THP_SSL: {THP_CERTFILE: 'cert-20220428-185313.crt', THP_KEYFILE: 'key-20220428-185313.pem'},
                     THP_REFERENCE: 'HTTPWELCOME'
                    },

    'HTTPSERVEFILE':  {THP_REPLY: TW_CRLF([b'HTTP/1.1 200 OK',
                                           b'Date: %TIME_GMT_RFC2822%',
                                           b'Content-Type: application/octet-stream',
                                           b'Content-Length: %CONTENT_LENGTH%',
                                           b'']) + FILECONTENTTOSERVE
                      },

    'HTTPSSERVEFILE': {THP_SSL: {THP_CERTFILE: 'cert-20220428-185313.crt', THP_KEYFILE: 'key-20220428-185313.pem'},
                       THP_REFERENCE: 'HTTPSERVEFILE'
                      },

    THP_DATA: {THP_FILES: {
                            'cert-20220428-185313.crt': {THP_CONTENT:
'''-----BEGIN CERTIFICATE-----
MIIE3jCCAsYCAQEwDQYJKoZIhvcNAQELBQAwNTELMAkGA1UEBhMCVVMxEDAOBgNV
BAoMB0V4YW1wbGUxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTIyMDQyODE2NTMx
NloXDTIzMDQyODE2NTMxNlowNTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1w
bGUxFDASBgNVBAMMC2V4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAsh+PMeQ+kSe8tUgfhzRboWY+T5BB9e6TBn//SnQsbyaASRtLJR/l
uyyZ4Jp13pYfshZExNGIJ0bB0XpMNU0L3CBy4js13fBZN7sOU4s35aI2fUDUrNH9
8xcH6g6MLXfylhenH4oATrugHpWb6D5rjoE9AkJ89vvMR53k3IueQINvMjWtr8BO
OxDoX3QiFTKCdDYtLl6/c4XvRzO/8e07ED/1WlWFxyyMu18AJJs1lQqr+SEyJKjR
cJmiFCHTq5QkguX0SG7FQK8iR48Cv2dw+KprKrWSKSP/FGJVxJ7Qxd+glHWYpXxc
ceDiT90Mjhgbj9bMEvjdxc0mpX93iZMSZyP/3Ffaqp1aONfmWNOkzkW3DFuDgSGF
pgfOF+7WPvzq6d/Z+XwbLk8jG9fu3y4klYSdX0cz9NDWuPj97vEGTQhaIn5U5PSw
XuRKJ90hieNUVaiB9m4gFYj7WqJCdBff3zu1KJn3XnrO+6a/ibM4PpqUeXzF17Wc
D1y77Sq1lBwf/C1mPNMY7ITDJdaIqutYrI8F4R5N7a6rAr4Of8EdmWb2prSpKTgY
nyWz95hfjYTPY+Y58jskzYb2j+PPg9dslSPkkfU7tIdT+R9cIkwT4OoZpiU6zcxN
j9qJS3ZZ1XB1B/RHEVqvzIYOZ/xm4paCRA3/nMdr9T69eNyPwJdYM+ECAwEAATAN
BgkqhkiG9w0BAQsFAAOCAgEAmX8roiCs6xCO5nnQhbIjD1ibm9QmjWcu+TQcEr8a
vGInPnGu9IEbuqrNn7pYud6KGQtJAnC66gPss629CvTy8EoMraWn8DubDmGus+8/
PdWDPevn3V3bR/vqxFftB3ebk/8IjXcLO27cywEbAzC9Y5IbkyIpWag0L6gbVWmX
DPvXAbEd+hzplCE1Aye/r0zY0Nx2xPoAXHSzZ2hf3Ii5KReD5Rpn5HYeW/5b6Em8
uPcotcx5M6Yq9A4y2qs9dNrBR2sR+CGPtjMXEbWJPWiy9VxDKPcl7pcvlgA4NXYd
V/OJQGDVVQJoAmOU7DHRvdwXP3A3JgaceHhfWAhnl8OUsLc4esnLt+dwvsLRx80L
ojYHxgTzplngfLMatzHYC1G0g/8Z6KAgoR8MZefLwL9BMG4ONdGeCbe9rTFs1yZP
wetzMKSXFmtERGQmweOQj7cSX60lPlnQ5/lzRc8FEhhLFtED21PjSA5+amOHxZoa
/+DtE6bYHRsmht7vDFFN+klxO3L0xj7goFcRsej7VU4ANaMKFGP7oH41C0oJcQGq
8iB8/pj3hYHORlAvE4yiGOZLf+4jPzY13lu3Sd2lzBVt+FWTi6fWzRwciXhGqcpe
YrYIyceFg/H5iBW7VzW7erTE90vGoBijH9Z0oUuAmbUPNYMW9FOLALCvTSvBhtZQ
XjM=
-----END CERTIFICATE-----
'''
                                                        },
                            'key-20220428-185313.pem': {THP_CONTENT:
'''-----BEGIN PRIVATE KEY-----
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
62gT0cjaZYsSv6QnJKz+MNyrhd3oNHo=
-----END PRIVATE KEY-----
'''
                                                        },
                          }},
}
