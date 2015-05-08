/*
SubstituteEachLine.js version 0.0.3
UltraEdit script to substitute each line of the active document with the corresponding template result
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
	2009/09/03: start
	2012/06/15: version 0.0.2 refactoring
	2013/12/30: version 0.0.3 columnmode, empty template line, empty last line
Todo:
	-
*/

function Main()
{
	var sTemplateLine = UltraEdit.getString("Enter template line (use %% as a placeholder): ", 1);
	
	if (sTemplateLine != "")
	{
		var bColumnMode = UltraEdit.columnMode;

		if (bColumnMode)
			UltraEdit.columnModeOff();

		UltraEdit.activeDocument.gotoLine(1, 1);
		for (var iIter = 1; !UltraEdit.activeDocument.isEof(); iIter++)
		{
			UltraEdit.activeDocument.gotoLine(iIter, 1);
			UltraEdit.activeDocument.selectLine();
			var sCurrentLine = UltraEdit.activeDocument.selection.replace(/[\r\n]+$/, "");
			UltraEdit.activeDocument.deleteToEndOfLine();
			if (!(UltraEdit.activeDocument.isEof() && sCurrentLine == ""))
				UltraEdit.activeDocument.write(sTemplateLine.replace(/%%/g, sCurrentLine));
		}

		if (bColumnMode)
			UltraEdit.columnModeOn();
	}
}

Main();
