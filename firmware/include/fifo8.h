/**
 * @file fifo8.h
 * @brief Circular byte-FIFO used for TPM command/response marshalling.
 *
 * Provides a ring-buffer of uint8_t elements with push, pop, peek,
 * bulk-copy and zero-copy pointer access.  Used internally by the
 * MARSHAL / UNMARSHAL macros in tpm2_spec_protocol.h to serialise
 * TPM command fields before MMIO transmission (§3 Transport Layer).
 */

#ifndef FIRMWARE_FIFO8_H
#define FIRMWARE_FIFO8_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Circular FIFO holding up to @c capacity bytes.
 *
 * @c head indexes the oldest element; @c num tracks occupancy.
 * Storage is heap-allocated by fifo8_create().
 */
typedef struct {
    uint8_t  *data;      /**< Heap-allocated backing buffer.   */
    uint32_t  capacity;  /**< Maximum number of stored bytes.  */
    uint32_t  head;      /**< Index of the oldest element.     */
    uint32_t  num;       /**< Current number of stored bytes.  */
} Fifo8;

/* --- Lifecycle ---------------------------------------------------------- */

/**
 * @brief Allocate the backing buffer and initialise the FIFO.
 * @param fifo     FIFO instance (caller-owned).
 * @param capacity Maximum number of bytes the FIFO can hold.
 */
void fifo8_create(Fifo8 *fifo, uint32_t capacity);

/**
 * @brief Free the backing buffer and zero all fields.
 * @param fifo FIFO instance previously initialised with fifo8_create().
 */
void fifo8_destroy(Fifo8 *fifo);

/* --- Push / Pop --------------------------------------------------------- */

/**
 * @brief Push a single byte. Asserts if the FIFO is full.
 */
void fifo8_push(Fifo8 *fifo, uint8_t data);

/**
 * @brief Push @p num bytes from @p data. Asserts if insufficient space.
 */
void fifo8_push_all(Fifo8 *fifo, const uint8_t *data, uint32_t num);

/**
 * @brief Pop and return the oldest byte. Asserts if empty.
 */
uint8_t fifo8_pop(Fifo8 *fifo);

/**
 * @brief Return the oldest byte without removing it. Asserts if empty.
 */
uint8_t fifo8_peek(Fifo8 *fifo);

/* --- Bulk copy ---------------------------------------------------------- */

/**
 * @brief Pop up to @p destlen bytes into @p dest.
 * @return Number of bytes actually popped.
 */
uint32_t fifo8_pop_buf(Fifo8 *fifo, uint8_t *dest, uint32_t destlen);

/**
 * @brief Copy up to @p destlen bytes into @p dest without consuming them.
 * @return Number of bytes actually copied.
 */
uint32_t fifo8_peek_buf(Fifo8 *fifo, uint8_t *dest, uint32_t destlen);

/* --- Zero-copy pointer access ------------------------------------------- */

/**
 * @brief Return a direct pointer to up to @p max contiguous bytes and pop them.
 * @param[in,out] fifo   The FIFO to read from.
 * @param[in]     max    Maximum number of bytes to pop.
 * @param[out]    numptr Receives the number of contiguous bytes available.
 * @return Pointer into the internal buffer (valid until next mutation).
 */
const uint8_t *fifo8_pop_bufptr(Fifo8 *fifo, uint32_t max, uint32_t *numptr);

/**
 * @brief Like fifo8_pop_bufptr() but does not consume the data.
 * @param[in,out] fifo   The FIFO to peek into.
 * @param[in]     max    Maximum number of bytes to peek.
 * @param[out]    numptr Receives the number of contiguous bytes available.
 */
const uint8_t *fifo8_peek_bufptr(Fifo8 *fifo, uint32_t max, uint32_t *numptr);

/* --- Misc --------------------------------------------------------------- */

/**
 * @brief Discard @p len bytes from the head. Asserts if @p len > occupancy.
 */
void fifo8_drop(Fifo8 *fifo, uint32_t len);

/**
 * @brief Reset the FIFO to empty without freeing the backing buffer.
 */
void fifo8_reset(Fifo8 *fifo);

/* --- Status ------------------------------------------------------------- */

/** @brief Return true if the FIFO contains no data. */
bool fifo8_is_empty(Fifo8 *fifo);

/** @brief Return true if the FIFO is at capacity. */
bool fifo8_is_full(Fifo8 *fifo);

/** @brief Return the number of free bytes remaining. */
uint32_t fifo8_num_free(Fifo8 *fifo);

/** @brief Return the number of bytes currently stored. */
uint32_t fifo8_num_used(Fifo8 *fifo);

#ifdef __cplusplus
}
#endif

#endif /* FIRMWARE_FIFO8_H */
