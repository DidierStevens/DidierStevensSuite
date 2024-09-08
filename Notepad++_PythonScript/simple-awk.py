#2024/09/07
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

def SimpleAwk():
    separator = notepad.prompt('Separator (default space character):', 'Provide a separator', ' ')
    template = notepad.prompt('Template ({1}, {2}, ...):', 'Provide a template', '{1}')
    options = notepad.prompt('Options (n for new document):', 'Provide options', '')
    if separator == None or template == None or options == None:
        return

    currentList = BufferToList()
    currentEOL = GetEOL()
    
    newList = []
    for item in currentList:
        line = template
        for index, field in  enumerate(item.split(separator)):
            line = line.replace('{%d}' % (index + 1), field)
        newList.append(line)

    if options == 'n':
        notepad.new()

    editor.setText(currentEOL.join(newList + ['']))

SimpleAwk()
