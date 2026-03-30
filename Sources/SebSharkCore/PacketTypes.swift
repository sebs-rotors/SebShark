//
//  PacketTypes.swift
//  SebShark
//
//  Created by Sebastian Sidor on 3/26/26.
//

// MARK: - Arena Layout

// Compile-time byte-offset map for the 512 MB mmap'd arena.
//
// Layout, low → high address:
//
//   [  0 MB – 300 MB)  PacketMetadata pool    300 MB   4,915,200 × 64-byte slots
//   [300 MB – 400 MB)  ConnectionState pool   100 MB     819,200 × 128-byte slots
//   [400 MB – 448 MB)  AlertRecord pool        48 MB     524,288 × 96-byte slots
//   [448 MB – 480 MB)  RulePattern pool        32 MB     131,072 × 256-byte slots
//   [480 MB – 512 MB)  Ring buffer             32 MB     1 contiguous region
//

public enum ArenaLayout {
    public static let totalBytes:       Int = 512 * 1024 * 1024
    
    public static let packetOffset:     Int = 0
    public static let packetBytes:      Int = 300 * 1024 * 1024
    public static let packetSlots:      Int = packetBytes / 64
    
    public static let connOffset:       Int = packetBytes
    public static let connBytes:        Int = 100 * 1024 * 1024
    public static let connSlots:        Int = connBytes / 128
    
    public static let alertOffset:      Int = connBytes + packetBytes
    public static let alertBytes:       Int = 48 * 1024 * 1024
    public static let alertSlots:       Int = alertBytes / 96
    
    public static let ruleOffset:       Int = alertBytes + connBytes + packetBytes
    public static let ruleBytes:        Int = 32 * 1024 * 1024
    public static let ruleSlots:        Int = ruleBytes / 256
    
    public static let ringOffset:       Int = ruleBytes + alertBytes + connBytes + packetBytes
    public static let ringBytes:        Int = 32 * 1024 * 24
}

// MARK: Enums

// TCP connection state machine (spec 2.7)
public enum TCPState: UInt8, Sendable {
    case empty          = 0
    case synSent        = 1
    case synRecv        = 2
    case established    = 3
    case finWait        = 4
    case closed         = 5
}

// Alert severity level (spec 4.3)
public enum AlertSeverity: UInt8, Sendable, CustomStringConvertible {
    case info           = 0
    case low            = 1
    case medium         = 2
    case high           = 3
    case critical       = 4
    
    public var description: String {
        switch self {
        case .info:     return "INFO"
        case .low:      return "LOW"
        case .medium:   return "MEDIUM"
        case .high:     return "HIGH"
        case .critical: return "CRITICAL"
        }
    }
}

// Alert category codes (spec 4.3)
public enum AlertCategory: UInt16, Sendable {
    case signatureMatch     = 0x0001
    case synFlood           = 0x0002
    case portScan           = 0x0003
    case rstInjection       = 0x0004
    case halfOpenStorm      = 0x0005
    case malformedPacket    = 0x0006
    case idleTimeout        = 0x0007
    case dnsTunnel          = 0x0008
    case arpSpoof           = 0x0009
    case fragmentAttack     = 0x000a
}

// Rule match conditions (spec 5.2)
public enum MatchType: UInt8, Sendable {
    case payloadContains    = 0x01
    case payloadStartsWith  = 0x02
    case tcpFlagsMatch      = 0x10
    case anomalyThreshold   = 0x20
}

// MARK: Slab Types

public struct PacketMetadata: Sendable {
    public var timestampNs:     UInt64 = 0
    public var captureLength:   UInt32 = 0
    public var wireLength:      UInt32 = 0
    public var ringOffset:      UInt32 = 0
    
    private var _pad:   UInt32 = 0
    private var _r0:    UInt64 = 0
    private var _r1:    UInt64 = 0
    private var _r2:    UInt64 = 0
    private var _r3:    UInt64 = 0
    private var _r4:    UInt64 = 0
}

public struct ConnectionState: Sendable {
    public var bytesFwd:        UInt64 = 0
    public var bytesRev:        UInt64 = 0
    public var firstSeenNs:     UInt64 = 0
    public var lastSeenNs:      UInt64 = 0
    public var srcIP:           UInt32 = 0
    public var dstIP:           UInt32 = 0
    public var packetsFwd:      UInt32 = 0
    public var packetsRev:      UInt32 = 0
    public var srcPort:         UInt16 = 0
    public var dstPort:         UInt16 = 0
    public var synCount:        UInt16 = 0
    public var lastSeqFwd:      UInt16 = 0
    public var lasSeqRev:       UInt16 = 0
    public var state:           UInt8 = 0
    public var seenFlags:       UInt8 = 0
    
    private var _pad:   UInt32 = 0
    private var _r0:    UInt64 = 0
    private var _r1:    UInt64 = 0
    private var _r2:    UInt64 = 0
    private var _r3:    UInt64 = 0
    private var _r4:    UInt64 = 0
    private var _r5:    UInt64 = 0
    private var _r6:    UInt64 = 0
    private var _r7:    UInt64 = 0
    private var _r8:    UInt64 = 0
}

public struct AlertRecord: Sendable {
    public var timestamp: UInt64 = 0
    public var chainHash0: UInt64 = 0
    public var chainHash1: UInt64 = 0
    public var chainHash2: UInt64 = 0
    public var chainHash3: UInt64 = 0
    public var alertID: UInt32 = 0
    public var srcIP: UInt32 = 0
    public var dstIP: UInt32 = 0
    public var ruleID: UInt32 = 0
    public var srcPort: UInt16 = 0
    public var dstPort: UInt16 = 0
    public var category: UInt16 = 0
    public var proto: UInt8 = 0
    public var severity: UInt8 = 0
    public var snapshot0: UInt64 = 0
    public var snapshot1: UInt64 = 0
    public var snapshot2: UInt64 = 0
    
    private var _reserved: UInt64 = 0
}

public struct RulePattern: Sendable {
    public var ruleID: UInt32 = 0
    public var matchType: UInt8 = 0
    public var severity: UInt8 = 0
    public var category: UInt8 = 0
    public var protocolFilter: UInt8 = 0
    public var flags: UInt8 = 0
    public var destPortFilter: UInt16 = 0
    public var patternLength: UInt8 = 0
    
    private var _diskPad0: UInt8 = 0
    private var _diskPad1: UInt8 = 0
    private var _diskPad2: UInt8 = 0
    
    public var pattern0: UInt64 = 0
    public var pattern1: UInt64 = 0
    public var pattern2: UInt64 = 0
    public var pattern3: UInt64 = 0
    public var pattern4: UInt64 = 0
    public var pattern5: UInt64 = 0
    
    // triple column to reduce visual noise for fields that currently carry no semantic meaning
    // will be populated later
    private var _c0:  UInt64 = 0; private var _c1:  UInt64 = 0; private var _c2:  UInt64 = 0;
    private var _c3:  UInt64 = 0; private var _c4:  UInt64 = 0; private var _c5:  UInt64 = 0;
    private var _c6:  UInt64 = 0; private var _c7:  UInt64 = 0; private var _c8:  UInt64 = 0;
    private var _c9:  UInt64 = 0; private var _c10: UInt64 = 0; private var _c11: UInt64 = 0;
    private var _c12: UInt64 = 0; private var _c13: UInt64 = 0; private var _c14: UInt64 = 0;
    private var _c15: UInt64 = 0; private var _c16: UInt64 = 0; private var _c17: UInt64 = 0;
    private var _c18: UInt64 = 0; private var _c19: UInt64 = 0; private var _c20: UInt64 = 0;
    private var _c21: UInt64 = 0; private var _c22: UInt64 = 0; private var _c23: UInt64 = 0;
}

// MARK: Layout Verification
public func verifySlotSizes() {
    precondition(
        MemoryLayout<PacketMetadata>.size == 64,
        "PacketMetadata expected size: 64, got \(MemoryLayout<PacketMetadata>.size)"
    )
    precondition(
        MemoryLayout<ConnectionState>.size == 128,
        "ConnectionState expected size: 128, got \(MemoryLayout<ConnectionState>.size)"
    )
    precondition(
        MemoryLayout<AlertRecord>.size == 96,
        "AlertRecord expected size: 96, got \(MemoryLayout<AlertRecord>.size)"
    )
    precondition(
        MemoryLayout<RulePattern>.size == 256,
        "RulePattern expected size: 256, got \(MemoryLayout<RulePattern>.size)"
    )
}
