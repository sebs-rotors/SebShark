//
//  main.swift
//  SebShark
//
//  Created by Sebastian Sidor on 3/17/26.
//

import SebSharkCore

print("SebShark sensor starting...")

do {
    let device = try BPFDevice(interface: "en0")
    print("BPF device opened, buffer size: \(device.bufferSize)B")
    print("Listening on en0...")

    while true {
        try device.read { framePtr, caplen in
            switch dissect(frame: framePtr, captureLength: caplen) {
            case .success(let packet):
                let s = packet.sourceIP
                let d = packet.destIP
                let src = "\((s >> 24) & 0xFF).\((s >> 16) & 0xFF).\((s >> 8) & 0xFF).\(s & 0xFF)"
                let dst = "\((d >> 24) & 0xFF).\((d >> 16) & 0xFF).\((d >> 8) & 0xFF).\(d & 0xFF)"
                print("\(src) → \(dst) | \(packet.transport)")
                print("\(src) → \(dst) | \(packet.transport)")
            case .failure(let err):
                break   // non-IPv4 or malformed — expected and fine
            }
        }
    }
} catch {
    print("Error: \(error)")
}
