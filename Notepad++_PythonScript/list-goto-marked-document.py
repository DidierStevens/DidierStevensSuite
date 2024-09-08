__description__ = "Notepad++ PythonScript plugin Python program to perform operations on lists: goto marked document"
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2024/09/07'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2024/09/07: start

Todo:
"""

def CheckIfMarked():
    try:
        markBufferID
    except NameError:
        return False
    return True

def Main():
    if CheckIfMarked():
        notepad.activateBufferID(markBufferID)
    else:
        notepad.messageBox('No document was marked!', 'Warning')

Main()
