------------------------------------------------------------------------
--- @file gtp.lua
--- @brief (gtp) utility.
--- Utility functions for the gtp_header structs 
--- Includes:
--- - gtp constants
--- - gtp header utility
--- - Definition of gtp packets
------------------------------------------------------------------------

--[[
-- Use this file as template when implementing a new gtpcol (to implement all mandatory stuff)
-- Replace all occurrences of gtp with your gtpcol (e.g. sctp)
-- Remove unnecessary comments in this file (comments inbetween [[...]]
-- Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- 				 if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - gtp/gtp.lua: add gtp.lua to the list so it gets loaded
--]]
local ffi = require "ffi"

require "utils"
require "proto.template"
local initHeader = initHeader

local ntoh, hton = ntoh, hton
local ntoh16, hton16 = ntoh16, hton16
local bswap = bit.bswap


---------------------------------------------------------------------------
---- GTP constants
---------------------------------------------------------------------------

--- GTP gtpcol constants
local gtp = {}


---------------------------------------------------------------------------
---- GTP header
---------------------------------------------------------------------------
-- TODO: Extension header is not well catched
gtp.headerFormat = [[
    uint8_t flags;
    uint8_t message;
    uint16_t length;
    uint32_t teid;
]]

--     uint16_t seqNo;
--     uint8_t nPduNo;
--     uint8_t nextExtHeader;
--     uint32_t extHeader;

--- Variable sized member
gtp.headerVariableMember = nil

--- Module for gtp_address struct
local gtpHeader = initHeader()
gtpHeader.__index = gtpHeader

--[[ for all members of the header with non-standard data type: set, get, getString 
-- for set also specify a suitable default value
--]]
----- Set the XYZ.
----- @param int XYZ of the gtp header as A bit integer.
--function gtpHeader:setXYZ(int)
--	int = int or 0
--end

--- Set flags.
--- @param flags Flags of the GTP header as 8 bit integer.
function gtpHeader:setFlags(flags)
	flags = flags or 0x30
	self.flags = flags
end

--- Retrieve flags.
--- @return Flags of the GTP header as 8 bit integer.
function gtpHeader:getFlags()
	return self.flags
end

--- Set message type.
--- @param type Message type of the GTP header as 8 bit integer.
function gtpHeader:setMessage(message)
    message = message or 0xFF
	self.message = message
end

--- Retrieve message type.
--- @return Message type as 8 bit integer.
function gtpHeader:getMessage()
	return self.message
end

--- Set the length of the GTP payload.
--- @param Length as 16 bit integer.
function gtpHeader:setLength(length)
	length = length or 1025
    self.length = hton16(length)
end

--- Retrieve the length of the GTP payload.
--- @return Length as 16 bit integer.
function gtpHeader:getLength()
	return hton16(self.length)
end

--- Set the Tunnel Endpoint Identifier (TEID).
--- @param TEID as 32 bit integer.
function gtpHeader:setTEID(teid)
	teid = teid or 100
    self.teid = ntoh(teid)
end

--- Retrieve the Tunnel Endpoint Identifier (TEID).
--- @return TEID as 32 bit integer.
function gtpHeader:getTEID()
	return ntoh(self.teid)
end

--- Set the sequence number.
--- @param Sequence number as 16 bit integer.
function gtpHeader:setSeqNo(seqNo)
	seqNo = seqNo or 0
    self.seqNo = hton16(seqNo)
end

--- Retrieve the sequence number.
--- @return Sequence number as 16 bit integer.
-- function gtpHeader:getSeqNo()
-- 	return hton16(self.seqNo)
-- end

--- Set the N-PDU number.
--- @param N-PDU number as 8 bit integer.
-- function gtpHeader:setNPduNo(nPduNo)
-- 	nPduNo = nPduNo or 0
--     self.nPduNo = nPduNo
-- end

--- Retrieve the N-PDU number.
--- @return N-PDU number as 8 bit integer.
-- function gtpHeader:getNPduNo()
-- 	return self.nPduNo
-- end

--- Set the Next extension header type.
--- @param nextExtHeader as 8 bit integer.
-- function gtpHeader:setNextExtHeader(nextExtHeader)
-- 	nextExtHeader = nextExtHeader or 0x85
--     self.nextExtHeader = nextExtHeader
-- end

--- Retrieve the the Next extension header type.
--- @return nextExtHeader as 8 bit integer.
-- function gtpHeader:getNextExtHeader()
-- 	return self.teid
-- end

--- Set the Extension header.
--- @param Extension header as 32 bit integer.
-- function gtpHeader:setExtHeader(extHeader)
-- 	extHeader = extHeader or 0x00010001
--     self.extHeader = extHeader
-- end

--- Retrieve the Extension header.
--- @return Extension header as 32 bit integer.
-- function gtpHeader:getExtHeader()
-- 	return ntoh(self.extHeader)
-- end


--- Set all members of the gtp header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: gtpXYZ
--- @param pre prefix for namedArgs. Default 'gtp'.
--- @code
--- fill() -- only default values
--- fill{ gtpXYZ=1 } -- all members are set to default values with the exception of gtpXYZ, ...
--- @endcode
function gtpHeader:fill(args, pre)
	args = args or {}
	pre = pre or "gtp"

	self:setFlags(args[pre .. "Flags"])
	self:setMessage(args[pre .. "Message"])
	self:setLength(args[pre .. "Length"])
	self:setTEID(args[pre .. "TEID"])
-- 	self:setSeqNo(args[pre .. "SeqNo"])
-- 	self:setNPduNo(args[pre .. "NPduNo"])
-- 	self:setNextExtHeader(args[pre .. "NextExtHeader"])
-- 	self:setExtHeader(args[pre .. "ExtHeader"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'gtp'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see gtpHeader:fill
function gtpHeader:get(pre)
	pre = pre or "gtp"

	local args = {}
	args[pre .. "Flags"] = self:getFlags()
	args[pre .. "Message"] = self:getMessage()
	args[pre .. "Length"] = self:getLength()
	args[pre .. "TEID"] = self:getTEID()
-- 	args[pre .. "SeqNo"] = self:getSeqNo()
-- 	args[pre .. "NPduNo"] = self:getNPduNo()
-- 	args[pre .. "nextExtHeader"] = self:getNextExtHeader()
-- 	args[pre .. "extHeader"] = self:getExtHeader()

	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function gtpHeader:getString()
	local retStr = "GTP "
	retStr = retStr .. "Flags " .. self:getFlags()
	retStr = retStr .. "Message " .. self:getMessage()
	retStr = retStr .. "Length" .. self:getLength()
	retStr = retStr .. "TEID " .. self:getTEID()
-- 	retStr = retStr .. "SeqNo " .. self:getSeqNo()
-- 	retStr = retStr .. "NPduNo " .. self:getNPduNo()
-- 	retStr = retStr .. "nextExtHeader " .. self:getNextExtHeader()
-- 	retStr = retStr .. "extHeader " .. self:getextHeader()

	return retStr
end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function gtpHeader:resolveNextHeader()
--- for now always return ipv4
	return 0x0800
end

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See gtp/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'gtp'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see gtpHeader:fill
function gtpHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

gtp.metatype = gtpHeader


return gtp
