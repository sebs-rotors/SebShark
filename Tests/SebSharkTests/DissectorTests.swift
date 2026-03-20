//
//  DissectorTests.swift
//  SebShark
//
//  Created by Sebastian Sidor on 3/19/26.
//

import Testing
@testable import SebSharkCore

// MARK: Test Packets

// Test vectors from section 6.1

// Packet 1: Ethernet + IPv4 + TCP SYN, 54B, no payload, no alert expected
private let packet1: [UInt8] = [
    // Ethernet
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, // dstMAC
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // srcMAC
    0x08, 0x00,                         // etherType IPv4
    
    // IPv4
    0x45, 0x00, 0x00, 0x28,             // v=4 ihl=5 len=40
    0x00, 0x01, 0x00, 0x00,             // id flags/frag
    0x40, 0x06, 0xB1, 0xC6,             // ttl=64 proto=TCP cksum
    0xC0, 0xA8, 0x01, 0x0A,             // src 192.168.1.10
    0xC0, 0xA8, 0x01, 0x01,             // dst 192.168.1.1
    
    // TCP
    0xC0, 0x00,                         // srcPort 49152
    0x00, 0x50,                         // dstPort 80
    0x00, 0x00, 0x00, 0x01,             // seqNum 1
    0x00, 0x00, 0x00, 0x00,             // ackNum 0
    0x50, 0x02,                         // doff=5 flags=SYN
    0xFF, 0xFF,                         // window
    0x00, 0x00, 0x00, 0x00,             // cksum urg
]

// Packet 2: Ethernet + IPv4 + TCP PSH+ACK + '/etc/passwd' payload, 85 bytes
private let packet2: [UInt8] = [
    // Ethernet
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    
    // IPv4
    0x45, 0x00, 0x00, 0x47,              // len=71
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x06, 0xB1, 0xA6,
    0xC0, 0xA8, 0x01, 0x0A,
    0xC0, 0xA8, 0x01, 0x01,
    
    // TCP
    0xC0, 0x00,
    0x00, 0x50,
    0x00, 0x00, 0x00, 0x02,              // seq 2
    0x00, 0x00, 0x00, 0x01,              // ack 1
    0x50, 0x18,                          // doff=5 flags=PSH+ACK
    0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
    
    // Payload: 'GET /etc/passwd HTTP/1.1\r\n\r\n' + padding
    0x47, 0x45, 0x54, 0x20,              // 'GET '
    0x2F, 0x65, 0x74, 0x63,              // '/etc'
    0x2F, 0x70, 0x61, 0x73,              // '/pas'
    0x73, 0x77, 0x64, 0x20,              // 'swd '
    0x48, 0x54, 0x54, 0x50,              // 'HTTP'
    0x2F, 0x31, 0x2E, 0x31,              // '/1.1'
    0x0D, 0x0A, 0x0D, 0x0A,              // '\r\n\r\n'
    0x00, 0x00, 0x00,                    // padding
]

// MARK: Shared errors

private enum DissectorTestError: Error {
    case unexpectedTransport
}

// MARK: Tests

@Suite("Dissector - Packet 1 (TCP SYN, no payload)")
struct Packet1Tests {
    let result: ParsedPacket
    let tcp: TCPFields
    
    init() throws {
        result = try (
            packet1.withUnsafeBytes { buf in
                dissect(frame: buf.baseAddress!, captureLength: buf.count)
            }.get()
        )
        guard case .tcp(let t) = result.transport else {
            throw DissectorTestError.unexpectedTransport
        }
        tcp = t
    }
    
    // Ethernet
    @Test func dstMAC() { #expect(result.dstMAC.bytes == (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01)) }
    @Test func srcMAC() { #expect(result.srcMAC.bytes == (0x11, 0x22, 0x33, 0x44, 0x55, 0x66)) }
    @Test func etherType() { #expect(result.etherType == 0x0800) }
    
    // IPv4
    @Test func ipVersion()     { #expect(result.ipVersion    == 4) }
    @Test func ipIHL()         { #expect(result.ipIHL        == 5) }
    @Test func ipTotalLength() { #expect(result.ipTotalLength == 40) }
    @Test func ipTTL()         { #expect(result.ipTTL        == 64) }
    @Test func ipProtocol()    { #expect(result.ipProtocol   == 6) }
    @Test func sourceIP()      { #expect(result.sourceIP     == 0xC0A8010A) }
    @Test func destIP()        { #expect(result.destIP       == 0xC0A80101) }
    
    // TCP
    @Test func srcPort()       { #expect(tcp.sourcePort     == 49152) }
    @Test func dstPort()       { #expect(tcp.destPort       == 80) }
    @Test func seqNum()        { #expect(tcp.sequenceNumber == 1) }
    @Test func ackNum()        { #expect(tcp.acknowledgment == 0) }
    @Test func flags()         { #expect(tcp.flags          == TCPFlags.syn) }
    @Test func dataOffset()    { #expect(tcp.dataOffset     == 5) }
    @Test func payloadLength() { #expect(tcp.payloadLength  == 0) }
    
    //    @Test func testFullRange() {
    //        #expect(
    //            result.dstMAC.bytes == (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01) &&
    //            result.srcMAC.bytes == (0x11, 0x22, 0x33, 0x44, 0x55, 0x66) &&
    //            result.etherType == 0x0800 &&
    //            result.ipVersion    == 4 &&
    //            result.ipIHL        == 5 &&
    //            result.ipTotalLength == 40 &&
    //            result.ipTTL        == 64 &&
    //            result.ipProtocol   == 6 &&
    //            result.sourceIP     == 0xC0A8010A &&
    //            result.destIP       == 0xC0A80101 &&
    //            tcp.sourcePort     == 49152 &&
    //            tcp.destPort       == 80 &&
    //            tcp.sequenceNumber == 1 &&
    //            tcp.acknowledgment == 0 &&
    //            tcp.flags          == TCPFlags.syn &&
    //            tcp.dataOffset     == 5 &&
    //            tcp.payloadLength  == 0
    //        )
    //    }
}
    
@Suite("Dissector — Packet 2 (TCP PSH+ACK, /etc/passwd payload)")
struct Packet2Tests {
    
    let result: ParsedPacket
    let tcp: TCPFields
    
    init() throws {
        result = try (
            packet2.withUnsafeBytes { buf in
                dissect(frame: buf.baseAddress!, captureLength: buf.count)
            }.get()
        )
        guard case .tcp(let t) = result.transport else {
            throw DissectorTestError.unexpectedTransport
        }
        tcp = t
    }
    
    @Test func ipTotalLength() { #expect(result.ipTotalLength == 71) }
    @Test func seqNum()        { #expect(tcp.sequenceNumber  == 2) }
    @Test func ackNum()        { #expect(tcp.acknowledgment  == 1) }
    @Test func flags()         { #expect(tcp.flags == TCPFlags.psh | TCPFlags.ack) }
    @Test func payloadOffset() { #expect(tcp.payloadOffset   == 54) }
    @Test func payloadLength() { #expect(tcp.payloadLength   == 31) }
    
    @Test func payloadStartBytes() {
        // Verify first 4 bytes of payload are 'GET '
        packet2.withUnsafeBytes { buf in
            let payloadStart = buf.baseAddress!.advanced(by: tcp.payloadOffset)
                .assumingMemoryBound(to: UInt8.self)
            #expect(payloadStart[0] == 0x47) // G
            #expect(payloadStart[1] == 0x45) // E
            #expect(payloadStart[2] == 0x54) // T
            #expect(payloadStart[3] == 0x20) // space
        }
    }
}
