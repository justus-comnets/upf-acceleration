local mg      = require "moongen"
local memory  = require "memory"
local device  = require "device"
local ts      = require "timestamping"
local stats   = require "stats"
local hist    = require "histogram"
local log     = require "log"
local limiter = require "software-ratecontrol"
local arp	 = require "proto.arp"
local pcap   = require "pcap"
local timer  = require "timer"
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
local SRC_IP		= "10.0.1.1"
local DST_IP		= "10.0.1.2"
local RAN_IP = "10.40.16.2"
local CORE_IP = "10.40.16.1"


function configure(parser)
    parser:description("Sent out packets on txDev to DUT. Captures all packets in and outgoing packets of DUT (similar to MoonSniff). ")
    parser:argument("txPort", "Device to sent from."):convert(tonumber)
    parser:argument("numPkts", "Number of packets which are sent in total."):convert(tonumber)
    parser:argument("pktRate", "Packet rate in Pps."):convert(tonumber)
    parser:argument("pktSize", "Size of packets."):convert(tonumber)
    parser:argument("inPort", "Device to receive ingoing packets to DUT."):convert(tonumber)
    parser:argument("outPort", "Device to receive outgoing packets from DUT."):convert(tonumber)

    parser:option("--poisson", "Use poisson distribution for packet rate."):default(false)
    parser:option("-if --infile", "Filename for the in traffic pcaps."):default("/tmp/in.test.pcap")
    parser:option("-of --outfile", "Filename for the out traffic pcaps."):default("/tmp/out.test.pcap")
    parser:option("--test-dev", "Specify two ports (tx, rx) for test device."):args(2):convert(tonumber)
    parser:option("--upload", "Load slave will sent GTP packets and test dev will decap."):args("?")


end

function master(args)
    local txDev = device.config{port = args.txPort, txQueues = 1, disableOffloads = rc ~= "moongen"}
    local inDev = device.config{port = args.inPort, rxQueues = 1, rxDescs = 4096, dropEnable = false}
    local outDev = device.config{port = args.outPort, rxQueues = 1, txQueues = 1, rxDescs = 4096, dropEnable = false}
    ETH_DST = outDev:getMac():getString()
    log:info("DUT MAC: %s", ETH_DST)

    local inTestDev, outTestDev
    if args.test_dev then
        log:info("Test device: %s %s", args.test_dev[1], args.test_dev[2])
        inTestDev = device.config{port = args.test_dev[1], rxQueues = 1, rxDescs = 4096, dropEnable = false}
        outTestDev = device.config{port = args.test_dev[2], txQueues = 1, rxDescs = 4096, dropEnable = false}
    end

    device.waitForLinks()

    if args.test_dev then
        stats.startStatsTask{txDevices = {txDev, outTestDev}, rxDevices = {inDev, outDev}}
    else
        stats.startStatsTask{txDevices = {txDev}, rxDevices = {inDev, outDev}}
    end

    inDev:enableRxTimestampsAllPackets(inDev:getRxQueue(0))
    outDev:enableRxTimestampsAllPackets(outDev:getRxQueue(0))

    ts.syncClocks(inDev, outDev)
    inDev:clearTimestamps()
    outDev:clearTimestamps()

    if args.test_dev then
        if not args.upload then
            mg.startTask("gtpEncap", inTestDev, outTestDev, args.pktSize)
        else
            mg.startTask("gtpDecap", inTestDev, outTestDev, args.pktSize)
        end
    end
    mg.startTask("dumper", inDev:getRxQueue(0), args.infile, "in")
    mg.startTask("dumper", outDev:getRxQueue(0), args.outfile, "out")
    mg.sleepMillis(1000)
    if args.upload then
        mg.startTask("loadSlaveGtp", txDev:getTxQueue(0), args.numPkts, args.pktRate, args.pktSize, args.poisson)
    else
        mg.startTask("loadSlave", txDev:getTxQueue(0), args.numPkts, args.pktRate, args.pktSize, args.poisson)
    end
    mg.waitForTasks()
end

local function pilotSignal(queue, pktRate, pktSize, gtp)
    local mem
    if gtp then
        mem = memory.createMemPool(function(buf)
            buf:getGtpUdpPacket():fill{
                ethSrc = queue,
                ethDst = ETH_DST,
                ip4Src = RAN_IP,
                ip4Dst = CORE_IP,
                udpSrc = 2152,
                udpDst = 2152,
                gtpTEID = 100,
                pktLength = pktSize + 36,
                nestedIp4Src = SRC_IP,
                nestedIp4Dst = DST_IP,
                nestedUdpSrc = 42069,
                nestedUdpDst = 42069,
            }
        end)
    else
        mem = memory.createMemPool(function(buf)
            buf:getUdpPacket():fill{
                ethSrc = queue,
                ethDst = ETH_DST,
                ip4Src = SRC_IP,
                ip4Dst = DST_IP,
                udpSrc = 42069,
                udpDst = 42069,
                pktLength = pktSize
            }
        end)
    end
	log:info("Start pilot signal")
	local bufs = mem:bufArray(1)
	local rateLimit = timer:new(1 / pktRate) -- timestamped packets
	local i = 0
	while i < (pktRate*10) do
		bufs:alloc(pktSize)
		bufs:offloadUdpChecksums()
		queue:send(bufs)
		rateLimit:wait()
		rateLimit:reset()
		i = i + 1
	end
	log:info("Finished pilot signal")
	return
end

function loadSlave(queue, numPkts, pktRate, pktSize, poisson)
    local mem = memory.createMemPool(function(buf)
        buf:getUdpPacket():fill{
            ethSrc = queue,
            ethDst = ETH_DST,
            ip4Src = SRC_IP,
            ip4Dst = DST_IP,
            udpSrc = 65000,
            udpDst = DST_PORT,
            pktLength = pktSize
        }
    end)
    log:info("Eth Src: %s", queue:getMacAddr():getString())

    pilotSignal(queue, pktRate, pktSize, false)

    local bufs = mem:bufArray()
    local rateLimit = timer:new(1 / pktRate)
    local pktId = 0
    while pktId < numPkts and mg.running() do
        bufs:alloc(pktSize)
        bufs:offloadUdpChecksums()
        for i, buf in ipairs(bufs) do
            if pktId >= numPkts then
                break
            end
            local pkt = buf:getUdpPacket()
            pkt.payload.uint64[2] = dpdkc.htobe64_export(pktId)
            pktId = pktId + 1
            queue:sendSingle(buf)
            rateLimit:wait()
            if poisson then
                poissonDelay = -ln(1 - random()) / pktRate
                rateLimit:reset(poissonDelay)
            else
                rateLimit:reset()
            end
        end
    end
    mg.sleepMillis(1000)
    mg.stop()
end

function loadSlaveGtp(queue, numPkts, pktRate, pktSize, poisson)
    local mem = memory.createMemPool(function(buf)
        buf:getGtpUdpPacket():fill{
            ethSrc = queue,
            ethDst = ETH_DST,
            ip4Src = RAN_IP,
            ip4Dst = CORE_IP,
            udpSrc = 2152,
            udpDst = 2152,
            gtpTEID = 100,
            pktLength = pktSize + 36,
            nestedIp4Src = SRC_IP,
            nestedIp4Dst = DST_IP,
            nestedUdpSrc = 65000,
            nestedUdpDst = DST_PORT,
        }
    end)
    log:info("Eth Src: %s", queue:getMacAddr():getString())

    pilotSignal(queue, pktRate, pktSize, true)

    local bufs = mem:bufArray()
    local rateLimit = timer:new(1 / pktRate)
    local pktId = 0
    while pktId < numPkts and mg.running() do
        bufs:alloc(pktSize + 36) -- minus 8 for the packet id
        bufs:offloadUdpChecksums()
        for i, buf in ipairs(bufs) do
            if pktId >= numPkts then
                break
            end
            local pkt = buf:getGtpUdpPacket()
            pkt.payload.uint64[2] = dpdkc.htobe64_export(pktId)
            pktId = pktId + 1
            queue:sendSingle(buf)
            rateLimit:wait()
            if poisson then
                poissonDelay = -ln(1 - random()) / pktRate
                rateLimit:reset(poissonDelay)
            else
                rateLimit:reset()
            end
        end
    end
    mg.sleepMillis(1000)
    mg.stop()
end

function dumper(queue, file, direction)
    local writer
    local captureCtr
    local tv_sec, tv_nsec = 0, 0
    writer = pcap:newWriterNS(file, 0)
--     captureCtr = stats:newPktRxCounter("Capture, thread " .. direction)
    local bufs = memory.bufArray()
    local drainQueue = timer:new(2)

    log:info("ready to receive")
    log:info("Capture %s traffic to file %s", direction, file)
    while drainQueue:running() do
        local rx = queue:tryRecv(bufs, 100)
        for i = 1, rx do
            tv_sec, tv_nsec = bufs[i]:getTimestampTS(queue.dev) -- TS adds 8 byte
--             if filter(bufs[i]) then
            writer:writeBufNano(tv_sec, tv_nsec, bufs[i], TRUNC_LEN)
--                 captureCtr:countPacket(bufs[i])
        end
        bufs:freeAll()
--         captureCtr:update()
        if mg.running() then
            drainQueue:reset()
        end
    end
--     captureCtr:finalize()
    log:info("Flushing buffers, this can take a while...")
    writer:close()
end


function filter(buf)
    local pkt = buf:getUdpPacket()
    if pkt.eth.type == bswap16(eth.TYPE_IP) and pkt.ip4.protocol == ip4.PROTO_UDP then
        local port = pkt.udp:getDstPort()
        if port == DST_PORT then
            return true
        else
            return false
        end
    end
end

function forward(inTestDev, outTestDev)
    local rxQueue = inTestDev:getRxQueue(0)
    local txQueue = outTestDev:getTxQueue(0)
    local bufs = memory.bufArray()

    while mg.running() do
        local count = rxQueue:recv(bufs)
        txQueue:sendN(bufs, count)
    end
--     captureCtr:finalize()
end

-- https://github.com/emmericp/MoonGen/blob/master/examples/vxlan-example.lua
function gtpEncap(inTestDev, outTestDev, pktSize)
    local rxQueue = inTestDev:getRxQueue(0)
    local txQueue = outTestDev:getTxQueue(0)

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
function gtpDecap(inTestDev, outTestDev, pktSize)
    local rxQueue = inTestDev:getRxQueue(0)
    local txQueue = outTestDev:getTxQueue(0)

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