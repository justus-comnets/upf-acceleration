local mg      = require "moongen"
local memory  = require "memory"
local device  = require "device"
local log     = require "log"
local eth    = require "proto.ethernet"
local ip4    = require "proto.ip4"
local udp    = require "proto.udp"
local dpdkc = require "dpdkc"
local ffi 	= require "ffi"
require "utils"
local hton16 = hton16

local TRUNC_LEN = 160
local PKT_SIZE	= 60
local DST_PORT = 65001
local ETH_DST	= "a0:36:9f:28:d9:a0"
local RAN_IP = "10.40.16.2"
local CORE_IP = "10.40.16.1"


function configure(parser)
    parser:description("Example of GTP processing for DPDK DUT. ")
    parser:argument("inPort", "Device to receive packets for DUT."):convert(tonumber)
    parser:argument("outPort", "Device to sent packets out of DUT."):convert(tonumber)
    parser:argument("pktSize", "Size of non-encapsulated packets."):convert(tonumber)
    parser:option("--decap", "DUT will decapsulate GTP packets."):args("?")
end

function master(args)
    local inDev = device.config{port = args.inPort, rxQueues = 1, rxDescs = 4096, dropEnable = false}
    local outDev = device.config{port = args.outPort, txQueues = 1, rxDescs = 4096, dropEnable = false}
    ETH_DST = outDev:getMac():getString()
    log:info("DUT MAC: %s", ETH_DST)
    device.waitForLinks()

    if not args.decap then
        mg.startTask("gtpEncap", inDev, outDev, args.pktSize)
    else
        mg.startTask("gtpDecap", inDev, outDev, args.pktSize)
    end
    mg.sleepMillis(1000)
    mg.waitForTasks()
end

-- https://github.com/emmericp/MoonGen/blob/master/examples/vxlan-example.lua
function gtpEncap(inDev, outDev, pktSize)
    local rxQueue = inDev:getRxQueue(0)
    local txQueue = outDev:getTxQueue(0)

    local encapsulationLen = 14 + 20 + 8 + 8

    local gtpMem = memory.createMemPool(function(buf)
    		buf:getGtpPacket():fill{
    			ethSrc = "a0:36:9f:28:d3:84",
                ethDst = "a0:36:9f:28:d9:82",
    			ip4Src = CORE_IP,
    			ip4Dst = RAN_IP,
    			udpSrc = 2152,
                udpDst = 2152,
    			gtpLength = pktSize - 14,
    		}
    end)

    local rxBufs = memory.bufArray()
    local gtpBufs = gtpMem:bufArray()

    while mg.running() do
        local count = rxQueue:recv(rxBufs)

        if count > 0 then
            -- https://github.com/emmericp/MoonGen/issues/320    allocN(x, 0) causes segfault
            gtpBufs:allocN(encapsulationLen + pktSize, count)
            for i = 1, count do
                local rxPkt = rxBufs[i]:getEthernetPacket()
                local pktSize = rxBufs[i]:getSize()
                local gtpPkt = gtpBufs[i]:getGtpPacket()
                ffi.copy(gtpPkt.payload, rxPkt.payload, pktSize)
                -- update size
                local totalSize = encapsulationLen + pktSize
                -- for the actual buffer
                gtpBufs[i]:setSize(totalSize)
                -- for the IP/UDP header
                gtpPkt:setLength(totalSize)
            end
            -- offload checksums
            gtpBufs:offloadUdpChecksums()
            txQueue:send(gtpBufs)
            -- free received packet
            rxBufs:freeAll()
        end
    end
--     captureCtr:finalize()
end

-- https://github.com/emmericp/MoonGen/blob/master/examples/vxlan-example.lua
function gtpDecap(inDev, outDev, pktSize)
    local rxQueue = inDev:getRxQueue(0)
    local txQueue = outDev:getTxQueue(0)

    local encapsulationLen = 20 + 8 + 8

    local decMem = memory.createMemPool(function(buf)
    		buf:getEthernetPacket():fill{
    			ethSrc = "a0:36:9f:28:d3:84",
                ethDst = "a0:36:9f:28:d9:82",
    		}
    	end)

    local rxBufs = memory.bufArray()
    local decBufs = decMem:bufArray()

    while mg.running() do
        local count = rxQueue:recv(rxBufs)

        if count > 0 then
            -- https://github.com/emmericp/MoonGen/issues/320    allocN(x, 0) causes segfault
            decBufs:allocN(encapsulationLen + pktSize, count)
            for i = 1, count do
    --             local rxPkt = rxBufs[i]:getIP4Packet()
                local gtpPkt = rxBufs[i]:getGtpPacket()
                local pktSize = rxBufs[i]:getSize()
    --             log:info("Packet size: %d", pktSize)
                local decPkt = decBufs[i]:getEthernetPacket()
                local payloadSize = rxBufs[i]:getSize() - encapsulationLen
                ffi.copy(decPkt.payload, gtpPkt.payload, pktSize)

                -- for the actual buffer
                decBufs[i]:setSize(payloadSize)

            end
            -- offload checksums
            decBufs:offloadUdpChecksums()
            txQueue:send(decBufs)
            -- free received packet
            rxBufs:freeAll()
        end
    end
--     captureCtr:finalize()
end