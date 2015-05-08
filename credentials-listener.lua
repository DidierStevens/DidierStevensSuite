--[[
	2013/11/26 - 2013/11/26
	credentials-listener.lua V0.0.1
	Wireshark Lua listener to extract credentials
	Example: tshark.exe -q -X lua_script:credentials-listener.lua -r test.pcapng
 
	Source code by Didier Stevens, GPL according to Wireshark Foundation ToS
	https://DidierStevens.com
	Use at your own risk

	Shortcommings, or todo's ;-)

	History:
		2013/11/26: start
--]]

local function MyToString(data)
	if data then
		return tostring(data)
	else
		return ''
	end
end

local function TableCount(table, key)
	if not table[key] then
		table[key] = 1
	else
		table[key] = table[key] + 1
	end
end

local function TableDump(table)
	for key, value in pairs(table) do
		print(key .. ': ' .. value)
	end
end

local function DefineHTTPAuthBasicCredentialsListener()
	local oTap = Listener.new(nil, 'http.authbasic')

	local oField_http_authbasic = Field.new('http.authbasic')

	local iCount = 0
	local tCredentials = {}

	function oTap.packet(pinfo, tvb, http)
		iCount = iCount + 1
		local sCredentials = MyToString(oField_http_authbasic())

		if sCredentials ~= '' then
			TableCount(tCredentials, sCredentials)
		end
	end

	function oTap.draw()
		print('HTTP: ' .. iCount)
		TableDump(tCredentials)
	end
end

local function DefineFTPCredentialsListener()
	local oTap = Listener.new(nil, 'ftp.request.command == "USER" or ftp.request.command == "PASS"')

	local oField_ftp_request_command = Field.new('ftp.request.command')
	local oField_ftp_request_arg = Field.new('ftp.request.arg')
	local oField_tcp_stream = Field.new('tcp.stream')

	local iCount = 0
	local tCredentials = {}
	local tStreamUser = {}

	function oTap.packet(pinfo, tvb, ftp)
		iCount = iCount + 1
		local sCommand = MyToString(oField_ftp_request_command())
		local sArg = MyToString(oField_ftp_request_arg())
		local sTCPStream = MyToString(oField_tcp_stream())

		if sCommand == '' or sTCPStream == '' or sArg == '' then
			return
		end

		if sCommand == 'USER' then
			tStreamUser[sTCPStream] = sArg
		end

		if sCommand == 'PASS' then
			local sCredentials = MyToString(tStreamUser[sTCPStream]) .. ':' .. sArg
			TableCount(tCredentials, sCredentials)
			tStreamUser[sTCPStream] = None
		end
	end

	function oTap.draw()
		print('FTP: ' .. iCount)
		TableDump(tCredentials)
	end
end

local function Main()
	DefineHTTPAuthBasicCredentialsListener()
	DefineFTPCredentialsListener()
end

Main()
