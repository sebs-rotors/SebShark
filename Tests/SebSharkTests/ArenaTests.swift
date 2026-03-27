//
//  ArenaTests.swift
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
    public static let totalBytes: Int = 512 * 1024 * 1024
    
    public static let packetOffset: Int = 0
    public static let packetBytes: Int = 300 * 1024 * 1024
    public static let packetSlots: Int = packetBytes / 64
    
    public static let connOffset: Int = packetBytes
    public static let connBytes: Int = 100 * 1024 * 1024
    public static let connSlots: Int = connBytes / 128
    
    public static let alertOffset: Int = connBytes + packetBytes
    public static let alertBytes: Int = 48 * 1024 * 1024
    public static let alertSlots: Int = alertBytes / 96
    
    public static let ruleOffset: Int = alertBytes + connBytes + packetBytes
    public static let ruleBytes: Int = 32 * 1024 * 1024
    public static let ruleSlots: Int = ruleBytes / 256
    
    public static let ringOffset: Int = ruleBytes + alertBytes + connBytes + packetBytes
    public static let ringBytes: Int = 32 * 1024 * 24
}
