//
//  BPFCapture.h
//  SebShark
//
//  Created by Sebastian Sidor on 3/20/26.
//

#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    BPF_OK                  = 0,
    BPF_ERR_NO_DEVICE       = 1,
    BPF_ERR_SBLEN           = 2,
    BPF_ERR_GBLEN           = 3,
    BPF_ERR_SETIF           = 4,
    BPF_ERR_IMMEDIATE       = 5,
    BPF_ERR_PROMISC         = 6,
    BPF_ERR_HDRCMPL         = 7,
    BPF_ERR_ALLOC           = 8,
    BPF_ERR_READ            = 9,
} BpfStatus;

typedef struct BpfDevice BpfDevice;

typedef void (*BpfFrameCallback)(const uint8_t *frame, uint32_t caplen, void *ctx);

BpfDevice *bpf_open(const char *interface, BpfStatus *status);

BpfStatus bpf_read(BpfDevice *dev, BpfFrameCallback handler, void *ctx);

void bpf_close(BpfDevice *dev);
