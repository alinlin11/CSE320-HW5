#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "protocol.h"
#include "csapp.h"
#include "debug.h"


int proto_send_packet(int fd, JEUX_PACKET_HEADER *hdr, void *data) {
    // Assume that the fields in packet are stored in network byte order
    debug("Calling send packets");
    
    // pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    // pthread_mutex_lock(&mutex);

    // Write header to fd
    if(rio_writen(fd, hdr, sizeof(JEUX_PACKET_HEADER)) < 0) {
        // pthread_mutex_unlock(&mutex);
        errno = EIO;
        return -1;
    }
        

    // Write payload size if there is one
    uint16_t payload_size = ntohs(hdr->size);
    if(payload_size > 0 && data != NULL) {
        if(rio_writen(fd, data, payload_size) < 0) {
            // pthread_mutex_unlock(&mutex);
            errno = EIO;
            return -1;
        }

    }

    // pthread_mutex_unlock(&mutex);

    return 0;
}

int proto_recv_packet(int fd, JEUX_PACKET_HEADER *hdr, void **payloadp) {
    // Uses malloc to allocate memory for payload
    // Pointer to the payload is stored in payloadp WHICH NEEDS TO BE FREED
    // Returned packet has to be in NETWORK BYTE ORDER

    debug("Calling recv packet");

    // Read header from fd

    int ret = rio_readn(fd, hdr, sizeof(JEUX_PACKET_HEADER));

    if (ret == -3) {
        hdr->type = JEUX_NO_PKT;
        return 0;
    }

    if (ret == -1) {
        errno = EIO;
        return -1;
    }

    // debug("Calling accept inv for id %d and role %d", hdr->id, hdr->role);
    
    // Convert header fields from network to host byte order
    // hdr->size = ntohs(hdr->size);
    // hdr->timestamp_sec = ntohl(hdr->timestamp_sec);
    // hdr->timestamp_nsec = ntohl(hdr->timestamp_nsec);

    // Allocate memory for payload
    uint16_t payload_size = ntohs(hdr->size);
    if(payload_size > 0) {
        *payloadp = malloc(payload_size);

        // Read payload data
        int bytes = rio_readn(fd, *payloadp, payload_size);

        if (bytes == -3) {
            free(*payloadp);
            hdr->type = JEUX_NO_PKT;
            return 0;
        }

        if(bytes == -1) {
            free(*payloadp);
            errno = EIO;
            return -1;
        }


    }

    return 0;
}