--[[
	2014/02/21 - 2014/02/21
	tcp-flags-dissector.lua V0.0.1
	Wireshark Lua tcp-flags postdissector example

	Source code by Didier Stevens, GPL according to Wireshark Foundation ToS
	https://DidierStevens.com
	Use at your own risk

	Shortcommings, or todo's ;-)

	History:
		2014/02/21: start
--]]

local function DecodeFlag(flags, mask, character)
	if bit.band(flags, mask) == 0 then
		return '*'
	else
		return character
	end
end

local function DefineAndRegisterTCPFlagsPostdissector()
	local oProtoTCPFlags = Proto('tcpflags', 'TCP Flags Postdissector')

	local oProtoFieldTCPFlags = ProtoField.string('tcpflags.flags', 'TCP Flags', 'The TCP Flags')

	oProtoTCPFlags.fields = {oProtoFieldTCPFlags}

	local oField_tcp_flags = Field.new('tcp.flags')

	function oProtoTCPFlags.dissector(buffer, pinfo, tree)
		local i_tcp_flags = oField_tcp_flags()
		local s_tcp_flags = ''

		if i_tcp_flags ~= nil then
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x80, 'C')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x40, 'E')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x20, 'U')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x10, 'A')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x08, 'P')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x04, 'R')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x02, 'S')
			s_tcp_flags = s_tcp_flags .. DecodeFlag(i_tcp_flags.value, 0x01, 'F')
			local oSubtree = tree:add(oProtoTCPFlags, 'TCP Flags')
			oSubtree:add(oProtoFieldTCPFlags, s_tcp_flags)
		end
	end

	register_postdissector(oProtoTCPFlags)
end

local function Main()
	DefineAndRegisterTCPFlagsPostdissector()
end

Main()
