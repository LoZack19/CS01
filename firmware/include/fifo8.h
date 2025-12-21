#ifndef FIRMWARE_FIFO8_H
#define FIRMWARE_FIFO8_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    uint32_t capacity;
    uint32_t head;
    uint32_t num;
} Fifo8;

void fifo8_create(Fifo8 *fifo, uint32_t capacity);
void fifo8_destroy(Fifo8 *fifo);

void fifo8_push(Fifo8 *fifo, uint8_t data);
void fifo8_push_all(Fifo8 *fifo, const uint8_t *data, uint32_t num);

uint8_t fifo8_pop(Fifo8 *fifo);
uint8_t fifo8_peek(Fifo8 *fifo);

uint32_t fifo8_pop_buf(Fifo8 *fifo, uint8_t *dest, uint32_t destlen);
uint32_t fifo8_peek_buf(Fifo8 *fifo, uint8_t *dest, uint32_t destlen);

const uint8_t *fifo8_pop_bufptr(Fifo8 *fifo, uint32_t max, uint32_t *numptr);
const uint8_t *fifo8_peek_bufptr(Fifo8 *fifo, uint32_t max, uint32_t *numptr);

void fifo8_drop(Fifo8 *fifo, uint32_t len);
void fifo8_reset(Fifo8 *fifo);

bool fifo8_is_empty(Fifo8 *fifo);
bool fifo8_is_full(Fifo8 *fifo);
uint32_t fifo8_num_free(Fifo8 *fifo);
uint32_t fifo8_num_used(Fifo8 *fifo);

#ifdef __cplusplus
}
#endif

#endif /* FIRMWARE_FIFO8_H */
