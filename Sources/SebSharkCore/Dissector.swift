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
