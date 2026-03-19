//
//  Dissector.swift
//  SebShark
//
//  Created by Sebastian Sidor on 3/17/26.
//

import Darwin

// MARK: Error

enum DissectError: Error, Sendable {
    case tooShort           // frame is smaller than required headers
    case notIPv4            // EtherType must be 0x0800
    case malformedIHL       // IP IHL field < 5 (minimum 20B header)
    case truncated          // a computed offset exceeds captureLength
}

// MARK: Result Types

struct MACAddress: Sendable {
    let bytes: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
}

struct UDPFields: Sendable {
    let sourcePort: UInt16
    let destPort: UInt16
    let length: UInt16
    let payloadOffset: Int
    let payloadLength: Int
}

enum TransportLayer: Sendable {
    case tcp(TCPFields)
    case udp(UDPFields)
    case icmp
    case other(UInt8)       // protocol number this dissector just cannot comprehend
}

struct ParsedPacket: Sendable {
    // Ethernet layer
    let dstMAC: MACAddress
    let srcMAC: MACAddress
    let etherType: UInt16
    
    // IPv4 (Network) layer
    let ipVersion: UInt8
    let ipIHL: UInt8
    let ipTotalLength: UInt16
    let ipTTL: UInt8
    let ipProtocol: UInt8
    
    // Transport layer
    let transport: TransportLayer
    
    // Original capture size
    let captureLength: Int
}

// TCP flag masks
enum TCPFlags {
    static let fin: UInt16 = 0x001
    static let syn: UInt16 = 0x002
    static let rst: UInt16 = 0x004
    static let psh: UInt16 = 0x008
    static let ack: UInt16 = 0x010
    static let urg: UInt16 = 0x020
}

// MARK: Dissector function
func dissect(frame: UnsafeRawPointer, captureLength: Int) -> Result<ParsedPacket, DissectError> {
    
    // Ethernet layer (14B min)
    guard captureLength >= 14 else { return .failure(.tooShort) }
    
    // Read MACs by loading individual bytes
    // No loadUnaligned for full byte range because there's no UInt48 to match 6B MACaddr size
    let dstMAC = MACAddress(bytes (
        frame.loadUnaligned(fromByteOffset: 0, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 1, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 2, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 3, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 4, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 5, as: UInt8.self),
    ))
    
    let srcMAC = MACAddress(bytes: (
        frame.loadUnaligned(fromByteOffset: 6, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 7, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 8, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 9, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 10, as: UInt8.self),
        frame.loadUnaligned(fromByteOffset: 11, as: UInt8.self),
    ))
    
    // EtherType is big-endian on the wire
    // Using bigEndian: to byte-swap for correct host byte order
    let etherType = UInt16(bigEndian:
                            frame.loadUnaligned(fromByteOffset: 12, as: UInt16.self)
    )
    
    // We only account for IPv4
    guard etherType = 0x0800 else { return .failure(.notIPv4) }
    
    // Network/IP layer (Starts at byte 14, minimum 20B)
    // TODO: network layer
}
