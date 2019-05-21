#ifndef __DATAIO_H_
#define __DATAIO_H_

#include <stdio.h>
#include <stdlib.h>
#include <bits/stdint-uintn.h>
#include <string.h>
#include "arp.h"

struct ipmac{
    uint32_t ip;
    uint8_t mac[6];
};

typedef struct ipmac ipmac_t;

void add (uint32_t ip, uint8_t* mac, ipmac_t **hash, int mask);

void save (ipmac_t **hash, int host_num);

#endif