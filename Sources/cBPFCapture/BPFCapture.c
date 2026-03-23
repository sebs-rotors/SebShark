//
//  BPFCapture.c
//  SebShark
//
//  Created by Sebastian Sidor on 3/20/26.
//

#include "CBPFCapture.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>

#DEFINE BPF_REQUESTED_BUFFER (2 * 1024 * 1024) // 2MB per spec

struct BpfDevice {
    int     fd;
    uint8_t *buffer;
    size_t  bufferSize;
}

// Simplifying repetitive error handling
static void xErr(int fd, BpfStatus *status, BpfStatus ErrNo) {
    close(fd);
    if (status) {
        *status = ErrNo;
    }
}

BpfDevice *bpf_open(const char *interface, BpfStatus *status) {
    // Acquire free BPF device
    int fd = -1;
    char path[16];
    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        fd = open(path, O_RDONLY);
        if (fd >= 0) break;
    }
    if (fd < 0) {
        xErr(fd, status, BPF_ERR_NO_DEVICE);
        return NULL;
    }
    
    // request kernel buffer
    u_int reqLen = BPF_REQUESTED_BUFFER;
    if (ioctl(fd, BIOCSBLEN, &reqLen) < 0) {
        xErr(fd, status, BPF_ERR_SBLEN);
        return NULL;
    }
    
    // read back actual buffer size
    u_int actualLen = 0;
    if (ioctl(fd, BIOCGBLEN, &actualLen) < 0) {
        xErr(fd, status, BPF_ERR_GBLEN);
        return NULL;
    }
    
    // bind to network interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        xErr(fd, status, BPF_ERR_SETIF);
        return NULL;
    }
    
    // immediate mode: deliver packets without waiting for buffer to fill
    u_int one = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) {
        xErr(fd, status, BPF_ERR_IMMEDIATE);
        return NULL;
    }
    
    // promiscuous mode: capture all traffic
    // TODO: check how promiscuous mode works without extra snooping setup. Does it just work?
    if (ioctl(fd, BIOCPROMISC, 0) < 0) {
        xErr(fd, status, BPF_ERR_PROMISC);
        return NULL;
    }
    
    // complete headers, no link-layer field autofill
    if (ioctl(fd, BIOCSHDRCMPL, &one) < 0) {
        xErr(fd, status, BPF_ERR_HDRCMPL);
        return NULL;
    }
    
    // allocate userspace read buffer
    uint8_t *buf = malloc(actualLen);
    if (!buf) {
        xErr(fd, status, BPF_ERR_ALLOC);
        return NULL;
    }
    
    BpfDevice *dev = malloc(sizeof(BpfDevice));
    if (!dev) {
        free(buf);
        xErr(fd, status, BPF_ERR_ALLOC);
        return NULL;
    }
    
    dev->fd             = fd;
    dev->buffer         = buf;
    dev->bufferSize     = actualLen;
    
    if (status) *status = BPF_OK;
    return dev;
}
