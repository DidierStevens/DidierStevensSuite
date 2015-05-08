/*
Substract.js version 0.0.1
UltraEdit script to mailmerge
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
	2014/08/08: start
	2014/08/09: added input validation

Todo:
	-
*/

function TestInput(sInput, iCountOpenFiles)
{
	return sInput == "" || isNaN(sInput) || +sInput < 0 || +sInput >= iCountOpenFiles;
}

function replaceAll(sData, sFind, sReplace)
{
  return sData.replace(new RegExp(sFind, 'g'), sReplace);
}

function GetDocument(documentIndex)
{
	UltraEdit.document[documentIndex].selectAll();
	return UltraEdit.document[documentIndex].selection;
}

function Document2Dictionary(documentIndex)
{
	var dDoc = [];

	UltraEdit.document[documentIndex].gotoLine(1, 1);
	for (var iIter = 1; !UltraEdit.document[documentIndex].isEof(); iIter++)
	{
		UltraEdit.document[documentIndex].gotoLine(iIter, 1);
		UltraEdit.document[documentIndex].selectLine();
		var sCurrentLine = UltraEdit.document[documentIndex].selection;
		dDoc[sCurrentLine] = 1;
	}

	return dDoc;
}

function GenerateDocument(sLine, sTemplate, sPath)
{
	var aItems = sLine.trim().split("\t");
	if (aItems.length > 1)
	{
		var sDocument = sTemplate;
		for (var iIter = 1; iIter < aItems.length; iIter++)
			sDocument = replaceAll(sDocument, "{TEMPLATEVARIABLE:" + iIter + "}", aItems[iIter]);
		UltraEdit.newFile();
		UltraEdit.activeDocument.write(sDocument);
		UltraEdit.saveAs(sPath + aItems[0]);
	}
}

function Main()
{
	var sMessageHelp = "The template document must contain {TEMPLATEVARIABLE:#} where # is a number.\nThe list document must contain records with fields separated by tabs.\nThe first field is the name of the file, the following fields are the template variables.\n{TEMPLATEVARIABLE:1} is the second field, {TEMPLATEVARIABLE:2} is the third field, ...";
	var sMessageTitle = "Mailmerge";
	var sMessageNumber = "Please enter a valid document number!";

	var iCountOpenFiles = UltraEdit.document.length;
	if (iCountOpenFiles < 2)
	{
		UltraEdit.messageBox("At least 2 files need to be open", sMessageTitle);
		return;
	}

	UltraEdit.outputWindow.clear();
	UltraEdit.outputWindow.showWindow(true);
	for (var iIter = 0; iIter < UltraEdit.document.length; iIter++)
		UltraEdit.outputWindow.write(iIter + ": " + UltraEdit.document[iIter].path);

	var sDocTemplate = UltraEdit.getString("Select template document (0-" + (iCountOpenFiles - 1) + ", see Output Window),\ntype h for help.", 1);
	if (sDocTemplate == "h")
	{
		UltraEdit.messageBox(sMessageHelp, sMessageTitle);
		return;
	}
	if (TestInput(sDocTemplate, iCountOpenFiles))
	{
		UltraEdit.messageBox(sMessageNumber, sMessageTitle);
		return;
	}

	var sDocList = UltraEdit.getString("Select list document (0-" + (iCountOpenFiles - 1) + ", see Output Window),\ntype h for help.", 1);
	if (sDocList == "h")
	{
		UltraEdit.messageBox(sMessageHelp, sMessageTitle);
		return;
	}
	if (TestInput(sDocList, iCountOpenFiles))
	{
		UltraEdit.messageBox(sMessageNumber, sMessageTitle);
		return;
	}

	var sFilename = UltraEdit.document[+sDocTemplate].path;
	var sTemplate = GetDocument(+sDocTemplate);
	var dDocList = Document2Dictionary(+sDocList);

	for (sLine in dDocList)
		GenerateDocument(sLine, sTemplate, sFilename.replace(/[^\\]*$/, ''));
}

Main();
