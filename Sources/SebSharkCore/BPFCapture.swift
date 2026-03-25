//
//  BPFCapture.swift
//  SebShark
//
//  Created by Sebastian Sidor on 3/20/26.
//

import Darwin
import cBPFCapture

// MARK: Errors

public enum BPFError: Error, Sendable {
    case noDevice
    case configFailed(BpfStatus)
    case readFailed
}

// MARK: BPF Device

public final class BPFDevice {
    private let handle: OpaquePointer   // BpfDevice *
    public let bufferSize: Int                 // kernel-granted size
    
    public init(interface: String) throws {
        var status = BPF_OK
        guard let h = interface.withCString({
            bpf_open($0, &status)
        }) else {
            throw BPFError.configFailed(status)
        }
        self.handle = h
        self.bufferSize = 0 // placeholder, not directly exposed. Will change if necessary
    }
    
    deinit {
        bpf_close(handle)
    }
    
    // MARK: Read
    // The read function on the Swift-side is really just trying to smuggle Swift closures through a C function
    // pointer boundary and back out the other side.
    public func read(handler: (UnsafeRawPointer, Int) -> Void) throws {
        try withoutActuallyEscaping(handler) { escapingHandler in
            
            // box closure so it can pass through void*
            let box = ClosureBox(escapingHandler)
            var status: BpfStatus
            let callback: BpfFrameCallback = { frame, caplen, ctx in
                guard let frame, let ctx else { return }
                Unmanaged<ClosureBox>
                    .fromOpaque(ctx)
                    .takeUnretainedValue()
                    .body(UnsafeRawPointer(frame), Int(caplen))
            }
            
            status = bpf_read(handle, callback, Unmanaged.passUnretained(box).toOpaque())
            guard status == BPF_OK else { throw BPFError.readFailed }
        }
    }
}

// The ClosureBox ensures we can pass in a void* type through bpf_read's *ctx argument
private final class ClosureBox {
    let body: (UnsafeRawPointer, Int) -> Void
    init(_ body: @escaping (UnsafeRawPointer, Int) -> Void) { self.body = body }
}
