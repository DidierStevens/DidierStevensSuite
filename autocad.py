#!/usr/bin/env python

__description__ = 'Script for cut-bytes.py to carve DWG files for VBA projects'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2026/10/04'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2026/09/23: start
  2026/10/04: continue

Todo:
"""

def AutoCAD(data):
    if len(data) < 40:
        raise Exception('File too short')

    dwg_version = data[0:6]
    if dwg_version[0:4] != b'AC10' or dwg_version[4:5] < b'0' or dwg_version[4:5] > b'9' or dwg_version[5:6] < b'0' or dwg_version[5:6] > b'9':
        raise Exception('MAGIC AutoCAD header not found')

    if dwg_version < b'AC1018':
        raise Exception('AutoCAD DWG version not supported: ' + dwg_version.decode())

    start_embedded_header = struct.unpack('<I', data[36:40])[0]
    if start_embedded_header == 0:
        return b''

    start_embedded_olefile = start_embedded_header + 16
    if start_embedded_olefile > len(data):
        raise Exception('start_embedded_olefile > len(data)')

    _, _, length_embedded_olefile, _ = struct.unpack('<IIII', data[start_embedded_header:start_embedded_olefile])
    if start_embedded_olefile + length_embedded_olefile > len(data):
        raise Exception('start_embedded_olefile + length_embedded_olefile > len(data)')

    return data[start_embedded_olefile:start_embedded_olefile+length_embedded_olefile]
