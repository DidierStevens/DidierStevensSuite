__description__ = "Notepad++ PythonScript plugin Python program to perform operations on lists"
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

import random

def GetCurentAndNextBufferID():
    currentBufferID = notepad.getCurrentBufferID()
    nextBufferID = None
    previousBufferId = None
    for item in notepad.getFiles():
        if previousBufferId == None and currentBufferID == item[1]:
            previousBufferId = currentBufferID
        elif previousBufferId != None:
            nextBufferID = item[1]
            break
    if nextBufferID != None:
        notepad.activateBufferID(nextBufferID)
    return currentBufferID, nextBufferID

def BufferToList(bufferID=None):
    if bufferID != None:
        currentBufferID = notepad.getCurrentBufferID()
        notepad.activateBufferID(bufferID)
    counter = 0
    items = []
    while True:
        try:
            line = editor.getLine(counter)
        except IndexError:
            break
        items.append(line.rstrip('\r\n'))
        counter += 1
    if bufferID != None:
        notepad.activateBufferID(currentBufferID)
    if len(items) > 1 and items[-1] == '':
        items = items[:-1]
    return items

def GetEOL(bufferID=None):
    if bufferID != None:
        currentBufferID = notepad.getCurrentBufferID()
        notepad.activateBufferID(bufferID)
    line = editor.getLine(0)
    if bufferID != None:
        notepad.activateBufferID(currentBufferID)
    if line.endswith('\r\n'):
        return '\r\n'
    elif line.endswith('\r'):
        return '\r'
    elif line.endswith('\n'):
        return '\n'
    else:
        raise Exception('Unknown EOL marker')

def CheckIfMarked():
    try:
        markBufferID
    except NameError:
        return False
    return True

def GetOperation():
    dOperations = {
        's': 'Subtract',
        'i': 'Intersect',
        'u': 'Union',
        'l': 'Listify',
        'r': 'Randomize',
    }
    operation = notepad.prompt('    '.join(['%s: %s' % item for item in dOperations.items()]) + '\nAdd suffix n to create a new document', 'Select the desired operation', '')
    if operation == None:
        return None, None

    operation = operation.lower()
    if operation.endswith('n'):
        newDocument = True
        operation = operation[:-1]
    else:
        newDocument = False
    if operation not in dOperations:
        notepad.messageBox('Error: unknown operation "%s"!' % operation, 'Error')
        return None, None
    return operation, newDocument

def Operation():
    operation, newDocument = GetOperation()
    if operation == None:
        return

    if not operation in ['l', 'r'] and not CheckIfMarked():
        notepad.messageBox('Error: mark a document first!', 'Error')
        return

    currentList = BufferToList()
    currentEOL = GetEOL()
    if not operation in ['l', 'r']:
        markedList = BufferToList(markBufferID)
    
    newList = []
    if operation == 's':
        for item in currentList:
            if not item in markedList:
                newList.append(item)
    elif operation == 'i':
        for item in currentList:
            if item in markedList:
                newList.append(item)
    elif operation == 'u':
        newList.extend(currentList)
        for item in markedList:
            if not item in currentList:
                newList.append(item)
    elif operation == 'r':
        newList.extend(currentList)
        random.shuffle(newList)
    elif operation == 'l':
        listifyFormat = notepad.prompt('<OPENLIST><SEPARATOR><CLOSELIST>', 'Provide the list format', '[, ]')
        if listifyFormat == None:
            return
        listify = listifyFormat[0] + listifyFormat[1:-1].join(currentList) + listifyFormat[-1]
        newList.append(listify)

    if newDocument:
        notepad.new()

    editor.setText(currentEOL.join(newList + ['']))

Operation()
