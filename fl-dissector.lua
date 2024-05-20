--[[
	2021/06/10 - 2024/05/18
	FLDISSECTOR-dissector.lua V0.0.1
	Wireshark Lua FLDISSECTOR protocol dissector (FL -> FieldLength)

	Source code by Didier Stevens, GPL according to Wireshark Foundation ToS
	https://DidierStevens.com
	Use at your own risk

	"c:\Program Files\Wireshark\Wireshark.exe" -X lua_script:fl-dissector.lua -X lua_script:port:12345 fl-example.pcapng

	arguments:

		-X lua_script:port:12345
		-X lua_script:protocolname:custom
		-X lua_script:fieldlengths:1,2:L,4:B
		-X lua_script:fieldnames:Type,Function,Value

	Shortcommings, or todo's ;-)
		add table with field description

	History:
		2021/06/10: start
		2024/05/15: continue
		2024/05/18: continue
		2024/05/19: continue
--]]

PROTOCOL = 'fldissector'
PORT = 1234
MAXIMUM_NUMBER_OF_FIELDS = 20
FIELDLENGTHS = '1'
FIELD_NAMES = {}
-- FIELD_NAMES = {[1]='start', [4]='command'}

local args = {...}

-- https://stackoverflow.com/questions/2421695/first-character-uppercase-lua
function Capitalize(str)
	return (str:gsub("^%l", string.upper))
end

function string:split(sDelimiter)
	if self:find(sDelimiter) == nil then
		return {{['field']=self, ['type']=''}}
	end

	local tResult = {}
	local iIndex = 1
	local iPositionSave = 1
	local sFieldSize
	local sFieldType
	for sPart, iPosition in self:gmatch('(.-)' .. sDelimiter .. '()') do
		local positionColon = sPart:find(':')
		if positionColon == nil then
			sFieldSize = sPart
			sFieldType = ''
		else
			sFieldSize = sPart:sub(1, positionColon - 1)
			sFieldType = sPart:sub(positionColon + 1)
		end
		tResult[iIndex] = {['field']=sFieldSize, ['type']=sFieldType}
		iIndex = iIndex + 1
		iPositionSave = iPosition
	end
	local sPart = self:sub(iPositionSave)
	local positionColon = sPart:find(':')
	if positionColon == nil then
		sFieldSize = sPart
		sFieldType = ''
	else
		sFieldSize = sPart:sub(1, positionColon - 1)
		sFieldType = sPart:sub(positionColon + 1)
	end
	tResult[iIndex] = {['field']=sFieldSize, ['type']=sFieldType} -- Handle the last field
	return tResult
end

function string:startswith(sStart)
	return self:sub(1, #sStart) == sStart
end

function string:startswithreturnremainder(sStart)
	if self:startswith(sStart) then
		return self:sub(#sStart + 1)
	end
	return nil
end

function splitup(sString, sFieldSizes)
	local tResult = {}
	local iIndex = 1
	local iPositionSave
	iPositionSave = 0
	tFieldSizes = sFieldSizes:split(',')
	for key1, value1 in pairs(tFieldSizes) do
		local iFieldSize = value1['field']
		if iPositionSave + iFieldSize > sString:len() then
			return tResult
		end
		tResult[iIndex] = {['field']=sString:subset(iPositionSave, iFieldSize), ['position']=iPositionSave}
		iIndex = iIndex + 1
		iPositionSave = iPositionSave + iFieldSize
	end
	if iPositionSave < sString:len() then
		tResult[iIndex] = {['field']=sString:subset(iPositionSave, sString:len() - iPositionSave), ['position']=iPositionSave} -- Handle the last field
	end
	return tResult
end

function GenerateFieldName(iKey)
	if FIELD_NAMES[iKey] == nil then
		return 'field' .. iKey
	else
		return FIELD_NAMES[iKey]
	end
end

function TableDump(table)
	for key, value in pairs(table) do
		print(key .. ': ' .. value['field'] .. ', ' .. value['type'])
	end
end

local function DefineAndRegisterFLDISSECTORdissector()
	local sProtocol = PROTOCOL
	local sFieldlengths = FIELDLENGTHS
	local iMaximumNumberOfFields = MAXIMUM_NUMBER_OF_FIELDS
	local iPort = PORT
	local iIter = 1
	local sFieldlengthsArgument = false

	while true do
		if args[iIter] == nil then
			break
		end

		argument = args[iIter]:startswithreturnremainder('port:')
		if argument ~= nil then
			iPort = tonumber(argument)
		end

		argument = args[iIter]:startswithreturnremainder('fieldnames:')
		if argument ~= nil then
			for key, value in pairs(argument:split(',')) do
				FIELD_NAMES[key] = value['field']
			end
		end

		argument = args[iIter]:startswithreturnremainder('protocolname:')
		if argument ~= nil then
			sProtocol = argument
		end

		argument = args[iIter]:startswithreturnremainder('fieldlengths:')
		if argument ~= nil then
			sFieldlengths = argument
			sFieldlengthsArgument = true
		end

		iIter = iIter + 1
	end

	local oProtoFLDISSECTOR = Proto(sProtocol, sProtocol:upper() .. ' Protocol')

	local oPref = oProtoFLDISSECTOR.prefs
	oPref.fieldlengths = Pref.string('Fieldlengths', sFieldlengths, 'Field lengths (comma separated)')
--	print(reset_preference(sProtocol .. '.' .. 'fieldlengths'))

	local tFieldSizeTypes
	if sFieldlengthsArgument then
		tFieldSizeTypes = sFieldlengths:split(',')
	else
		tFieldSizeTypes = oPref.fieldlengths:split(',')
	end

	for iter = 1, iMaximumNumberOfFields do
		sFieldname = GenerateFieldName(iter)
		if tFieldSizeTypes[iter] == nil or tFieldSizeTypes[iter] ~= nil and tFieldSizeTypes[iter]['type'] == '' then
			oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.bytes(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), 'Content of ' .. sFieldname)
		else
			if tFieldSizeTypes[iter]['field'] == '1' then
				oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.uint8(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), base.DEC, nil, nil, 'Content of ' .. sFieldname)
			elseif tFieldSizeTypes[iter]['field'] == '2' then
				oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.uint16(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), base.DEC, nil, nil, 'Content of ' .. sFieldname)
			elseif tFieldSizeTypes[iter]['field'] == '3' then
				oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.uint24(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), base.DEC, nil, nil, 'Content of ' .. sFieldname)
			elseif tFieldSizeTypes[iter]['field'] == '4' then
				oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.uint32(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), base.DEC, nil, nil, 'Content of ' .. sFieldname)
			else
				oProtoFLDISSECTOR.fields[sFieldname] = ProtoField.bytes(sProtocol .. '.' .. sFieldname, Capitalize(sFieldname), 'Content of ' .. sFieldname)
			end
		end
	end

	function oProtoFLDISSECTOR.dissector(oTvbProtocolData, oPinfo, oTreeItemRoot)
		local sProtocolName = oProtoFLDISSECTOR.name

		local iProtocolDataLength = oTvbProtocolData:len()

		if iProtocolDataLength == 0 then
			return
		end

		local sFLData = oTvbProtocolData():bytes()

		local oTreeItemFLDISSECTOR = oTreeItemRoot:add(oProtoFLDISSECTOR, oTvbProtocolData(), sProtocolName .. ' Protocol Data')

		local tFields
		if sFieldlengthsArgument then
			tFields = splitup(sFLData, sFieldlengths)
		else
			tFields = splitup(sFLData, oPref.fieldlengths)
		end

		local iCountFields = 0
		for key1, value1 in pairs(tFields) do
			if key1 <= iMaximumNumberOfFields then
				sFieldname = GenerateFieldName(key1)
				if tFieldSizeTypes[key1] == nil or tFieldSizeTypes[key1] ~= nil and tFieldSizeTypes[key1]['type'] == '' then
					oTreeItemFLDISSECTOR:add(oProtoFLDISSECTOR.fields[sFieldname], oTvbProtocolData(value1['position'], value1['field']:len()))
				else
					if tFieldSizeTypes[key1]['type']:lower() == 'l' then
						oTreeItemFLDISSECTOR:add(oProtoFLDISSECTOR.fields[sFieldname], oTvbProtocolData(value1['position'], value1['field']:len()), oTvbProtocolData(value1['position'], value1['field']:len()):le_uint())
					else
						oTreeItemFLDISSECTOR:add(oProtoFLDISSECTOR.fields[sFieldname], oTvbProtocolData(value1['position'], value1['field']:len()), oTvbProtocolData(value1['position'], value1['field']:len()):uint())
					end
				end
			end
			iCountFields = iCountFields + 1
		end

		if iCountFields > iMaximumNumberOfFields then
			error('Maximum number of fields exceeded, increase iMaximumNumberOfFields (= ' .. iMaximumNumberOfFields .. ') in the code of the FL dissector to at least ' .. iCountFields)
		end
	end

	DissectorTable.get('tcp.port'):add(iPort, oProtoFLDISSECTOR)
end

local function Main()
	DefineAndRegisterFLDISSECTORdissector()
end

Main()
