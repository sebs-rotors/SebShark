# SebShark

A real-time network intrusion detection system (NIDS) for macOS, built in Swift 6.

Captures raw ethernet frames via the Darwin Berkeley Packet Filter (BPF) in C, dissects Ethernet/IPv4/TCP/UDP headers in pure Swift, and (in progress) detects threats using SIMD-accelerated pattern matching against a rule engine.

## Status

Early development. Current progress:

|
 Component 
|
 Status 
|
---
|
 BPF packet capture
|
 Done
|

|
 Protocol Dissector
|
 Done
|

|
 Memory arena / packet slab allocator
|
 IN PROGRESS
|

|
 SIMD pattern matching engine
|
 Not started
|

|
 Cryptographic log integrity (HMAC-SHA256)
|
 Not started
|

|
 kqueue event loop
|
 Not started
|

|
 a pretty gui
|
 Not started
|

## Requirements
- macOS 14+ (Sonoma)
- Xcode 16+
- Swift 6.0+
- Root privileges (required for BPF device access)

## Running
```
sudo swift run SebShark
```

