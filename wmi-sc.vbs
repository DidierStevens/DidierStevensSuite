' wmi-sc.vbs
' Display WMI SecurityCenter AV and FW data (XP and Vista only)
' Source code put in public domain by Didier Stevens, no Copyright
' https://DidierStevens.com
' Use at your own risk
'
'History:
'  2011/01/23: start

strComputer = "."

On Error Resume Next

MsgBox "Start"

Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\SecurityCenter")
Set colItems = oWMI.ExecQuery("Select * from AntiVirusProduct")

If Err = 0 Then
	For Each objAntiVirusProduct In colItems
		strMessage = ""
		strMessage = strMessage & objAntiVirusProduct.companyName & vbCRLF
		strMessage = strMessage & objAntiVirusProduct.displayName & vbCRLF
		strMessage = strMessage & objAntiVirusProduct.onAccessScanningEnabled & vbCRLF
		strMessage = strMessage & objAntiVirusProduct.productUptoDate & vbCRLF
		strMessage = strMessage & objAntiVirusProduct.versionNumber & vbCRLF
		MsgBox strMessage, , "AntiVirus SecurityCenter"
	Next
Else
	strMessage = ""
	strMessage = strMessage & "Error Number: " & Err.Number & vbCRLF
	strMessage = strMessage & "Error Source: " & Err.Source & vbCRLF
	strMessage = strMessage & "Error Description: " & Err.Description & vbCRLF
	MsgBox strMessage
	Err.Clear
End If

Set colItems = oWMI.ExecQuery("Select * from FirewallProduct")

If Err = 0 Then
	For Each objFirewallProduct In colItems
		strMessage = ""
		strMessage = strMessage & objFirewallProduct.companyName & vbCRLF
		strMessage = strMessage & objFirewallProduct.displayName & vbCRLF
		strMessage = strMessage & objFirewallProduct.enabled & vbCRLF
		strMessage = strMessage & objFirewallProduct.versionNumber & vbCRLF
		MsgBox strMessage, , "Firewall SecurityCenter"
	Next
Else
	strMessage = ""
	strMessage = strMessage & "Error Number: " & Err.Number & vbCRLF
	strMessage = strMessage & "Error Source: " & Err.Source & vbCRLF
	strMessage = strMessage & "Error Description: " & Err.Description & vbCRLF
	MsgBox strMessage
	Err.Clear
End If

Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\SecurityCenter2")
If Err.Number = -2147217394 Then
	Err.Clear
	MsgBox "WMI Class SecurityCenter2 not found"
Else
	Set colItems = oWMI.ExecQuery("Select * from AntiVirusProduct")
	
	If Err = 0 Then
		For Each objAntiVirusProduct In colItems
			strMessage = ""
			strMessage = strMessage & objAntiVirusProduct.displayName & vbCRLF
			strMessage = strMessage & objAntiVirusProduct.productState & vbCRLF
			MsgBox strMessage, , "AntiVirus SecurityCenter2"
		Next
	Else
		strMessage = ""
		strMessage = strMessage & "Error Number: " & Err.Number & vbCRLF
		strMessage = strMessage & "Error Source: " & Err.Source & vbCRLF
		strMessage = strMessage & "Error Description: " & Err.Description & vbCRLF
		MsgBox strMessage
		Err.Clear
	End If
	
	Set colItems = oWMI.ExecQuery("Select * from FirewallProduct")
	
	If Err = 0 Then
		For Each objFirewallProduct In colItems
			strMessage = ""
			strMessage = strMessage & objFirewallProduct.companyName & vbCRLF
			strMessage = strMessage & objFirewallProduct.displayName & vbCRLF
			strMessage = strMessage & objFirewallProduct.enabled & vbCRLF
			strMessage = strMessage & objFirewallProduct.versionNumber & vbCRLF
			MsgBox strMessage, , "Firewall SecurityCenter2"
		Next
	Else
		strMessage = ""
		strMessage = strMessage & "Error Number: " & Err.Number & vbCRLF
		strMessage = strMessage & "Error Source: " & Err.Source & vbCRLF
		strMessage = strMessage & "Error Description: " & Err.Description & vbCRLF
		MsgBox strMessage
		Err.Clear
	End If
End If

MsgBox "Done"
