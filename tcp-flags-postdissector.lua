--[[
	2014/05/26 - 2014/05/26
	tcp-flags-postdissector.lua V0.0.1
	Wireshark Lua tcp-flags postdissector example

	Source code by Didier Stevens, GPL according to Wireshark Foundation ToS
	https://DidierStevens.com
	Use at your own risk

	Shortcommings, or todo's ;-)

	History:
		2014/05/26: start
--]]

local function DefineAndRegister_tcpflags_postdissector()
	local oProto_tcpflags = Proto('tcpflags', 'TCP Flags Postdissector')

	local oProtoFieldflags = ProtoField.string('tcpflags.flags', 'TCP Flags', 'The TCP Flags')
	oProto_tcpflags.fields = {oProtoFieldflags}

	local oField_tcp_flags = Field.new('tcp.flags')

	function oProto_tcpflags.dissector(buffer, pinfo, tree)
		local tcp_flags = oField_tcp_flags()

		if tcp_flags  ~= nil then
			local oSubtree = tree:add(oProto_tcpflags, 'TCP Flags')
			oSubtree:add(oProtoFieldflags, tcp_flags.value)
		end

	end

	register_postdissector(oProto_tcpflags)
end

local function Main()
	DefineAndRegister_tcpflags_postdissector()
end

Main()

