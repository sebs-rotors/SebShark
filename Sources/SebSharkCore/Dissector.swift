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
    
    // Network/IP layer (Starts at byte 14, minimum 20B)
    
    // We only account for IPv4
    guard etherType = 0x0800 else { return .failure(.notIPv4) }
    guard captureLength >= 34 else { return .failure(.tooShort) }
    
    let versionIHL  = frame.loadUnaligned(fromByteOffset: 14, as: UInt8.self)
    let ipVersion   = versionIHL >> 4
    let ipIHL       = versionIHL & 0x0F
    
    guard ipIHL >= 5 else { return .failure(.malformedIHL) }
    
    let ipHeaderLength = Int(ipIHL) * 4
    guard captureLength >= 14 + ipHeaderLength else { return .failure(.truncated) }
    
    // Total length is full datagram size including IP header
    let ipTotalLength = UInt16(bigEndian:
        frame.loadUnaligned(fromByteOffset: 16, as: UInt16.self)
    )
    let ipTTL = frame.loadUnaligned(fromByteOffset: 22, as: UInt8.self)
    let ipProtocol = frame.loadUnaligned(fromByteOffset: 23, as: UInt8.self)
    let sourceIP = UInt32(bigEndian:
        frame.loadUnaligned(fromByteOffset: 26, as: UInt32.self)
    )
    let destIP = UInt32(bigEndian:
        frame.loadUnaligned(fromByteOffset: 30, as: UInt32.self)
    )
    
    // Transport Layer
    let transportOffset = 14 + ipHeaderLength
    let transport: TransportLayer
    
    switch ipProtocol {
        
    case 1:
        transport = .icmp
        
    case 6: // TCP - min 20B header
        guard captureLength >= transportOffset + 20 else { return .failure(.truncated) }
        
        let srcPort = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset, as: UInt16.self)
        )
        let dstPort = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 2, as: UInt16.self)
        )
        let seqNum = UInt32(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 4, as: UInt32.self)
        )
        let ackNum = UInt32(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 8, as: UInt32.self)
        )
        
        // transportOffset +12/+13:
        // upper 4  -> data offset (TCP header size, 32-bit words)
        // lower 12 -> TCP flags
        let dataOffsetAndFlags = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 12, as: UInt16.self)
        )
        let dataOffset  = UInt8(dataOffsetAndFlags >> 12)
        let flags       = dataOffsetAndFlags & 0x0FFF
        
        let windowSize = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 14, as: UInt16)
        )
        
        let tcpHeaderLength = Int(dataOffset) * 4
        let payloadOffset = transportOffset + tcpHeaderLength
        
        let payloadLength = Int(ipTotalLength) - ipHeaderLength - tcpHeaderLength
        
        guard payloadOffset <= captureLength    else { return .failure(.truncated) }
        guard payloadOffset >= 0                else { return .failure(.truncated) }
        
        transport = .tcp(TCPFields(
            sourcePort:     srcPort,
            destPort:       dstPort,
            sequenceNumber: seqNum,
            acknowledgment: ackNum,
            dataOffset:     dataOffset,
            flags:          flags,
            windowSize:     windowSize,
            payloadOffset:  payloadOffset,
            payloadLength:  payloadLength
        ))
        
    case 17: // UDP - 8B header
        guard captureLength >= transportOffset + 8 else { return .failure(.truncated) }
        
        let srcPort = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset, as: UInt16)
        )
        let dstPort = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 2, as: UInt16)
        )
        let udpLength = UInt16(bigEndian:
            frame.loadUnaligned(fromByteOffset: transportOffset + 4, as: UInt16)
        )
        
        let payloadOffset = transportOffset + 8
        let payloadLength = Int(udpLength) - 8
        
        guard payloadOffset <= captureLength    else { return .failure(.truncated) }
        guard payloadLength <= 0                else { return .failure(.truncated) }
        
        transport = .udp(
            sourcePort      = srcPort,
            destPort        = dstPort,
            length:         = udpLength,
            payloadOffset:  = payloadOffset,
            payloadLength:  = payloadLength
        ))

    default:
        transport = .other(ipProtocol)
    }
    
    return .success(ParsedPacket(
        dstMAC:             dstMAC,
        srcMAC:             srcMAC,
        etherType:          etherType,
        ipVersion:          ipVersion,
        ipIHL:              ipIHL,
        ipTotalLength:      ipTotalLength,
        ipTTL:              ipTTL,
        ipProtocol:         ipProtocol,
        transport:          transport,
        captureLength:      captureLength
    ))
}
