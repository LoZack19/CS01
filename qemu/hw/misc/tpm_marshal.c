#include "include/hw/misc/s32k358_tpm.h"

void unmarshal(void *data, size_t size, Fifo8 *fifo) {
    for (size_t i = 0; i < size; i++) {
        ((uint8_t *)data)[i] = fifo8_pop(fifo);
    }
}

void marshal(Fifo8 *fifo, const void *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        fifo8_push(fifo, ((uint8_t *)data)[i]);
    }
}