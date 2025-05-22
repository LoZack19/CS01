#ifndef S32K358_LPUART_H
#define S32K358_LPUART_H

#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "chardev/char-fe.h"
#include "qapi/error.h"
#include "qemu/timer.h"
#include "hw/registerfields.h"
#include "qom/object.h"
#include "hw/qdev-clock.h"

#define TYPE_S32K358_LPUART "s32k358-lpuart"
OBJECT_DECLARE_SIMPLE_TYPE(s32k358LPUARTState, S32K358_LPUART)

#define VERID_RST 0x00000000
#define PARAM_RST 0x00000000
#define GLOBAL_RST 0x00000000
#define PINCFG_RST 0x00000000
#define BAUD_RST 0x0F000004
#define STAT_RST 0x00C00000
#define CTRL_RST 0x00000000
#define DATA_RST 0x00001000
#define MATCH_RST 0x00000000
#define MODIR_RST 0x00000000
#define FIFO_RST 0x00000000
#define WATER_RST 0x00000000
#define DATARO_RST 0x00001000
#define MCR_RST 0x00000000
#define MSR_RST 0x00000000
#define REIR_RST 0x00000000
#define TEIR_RST 0x00000000
#define HDCR_RST 0x00000000
#define TOCR_RST 0x00000000
#define TOSR_RST 0x0000000F
#define TIMEOUT0_RST 0x00000000
#define TIMEOUT1_RST 0x00000000
#define TIMEOUT2_RST 0x00000000
#define TIMEOUT3_RST 0x00000000

/* --- Core Register Block --- */
REG32(VERID,    0x000)
REG32(PARAM,    0x004)  
REG32(GLOBAL,   0x008)
    FIELD(GLOBAL, RST, 1, 1)
REG32(PINCFG,   0x00C)
REG32(BAUD,     0x010)
    FIELD(BAUD, OSR, 24, 5)
    FIELD(BAUD, SBR, 0, 13)
REG32(STAT,     0x014)  
    FIELD(STAT, RDRF, 21, 1)
REG32(CTRL,     0x018)
    FIELD(CTRL, TIE, 23, 1)
    FIELD(CTRL, TCIE, 22, 1)
    FIELD(CTRL, RIE, 21, 1)
    FIELD(CTRL, RE, 18, 1)
    FIELD(CTRL, M7, 11, 1)
    FIELD(CTRL, M, 4, 1)
REG32(DATA,     0x01C)  
REG32(MATCH,    0x020)
REG32(MODIR,    0x024)
REG32(FIFO,     0x028)  
REG32(WATER,    0x02C)  
REG32(DATARO,   0x030)

REG32(MCR,      0x040)
REG32(MSR,      0x044)
REG32(REIR,     0x048)
REG32(TEIR,     0x04C)
REG32(HDCR,     0x050)

REG32(TOCR,     0x058)
REG32(TOSR,     0x05C)

REG32(TIMEOUT0, 0x060)
REG32(TIMEOUT1, 0x064)
REG32(TIMEOUT2, 0x068)
REG32(TIMEOUT3, 0x06C)

struct s32k358LPUARTState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    CharBackend chr;
    Clock *clk;
    qemu_irq irq;

    uint32_t verid;
    uint32_t param;
    uint32_t global;
    uint32_t pincfg;
    uint32_t baud;
    uint32_t stat;
    uint32_t ctrl;
    uint32_t data;
    uint32_t match;
    uint32_t modir;
    uint32_t fifo;
    uint32_t water;
    uint32_t dataro;
    uint32_t mcr;
    uint32_t msr;
    uint32_t reir;
    uint32_t teir;
    uint32_t hdcr;
    uint32_t tocr;
    uint32_t tosr;
    uint32_t timeout0;
    uint32_t timeout1;
    uint32_t timeout2;
    uint32_t timeout3;
};

static inline uint32_t LPUART_BAUD_RATE(s32k358LPUARTState *s) {
    uint32_t sbr = FIELD_EX32(s->baud, BAUD, SBR);
    uint32_t osr = FIELD_EX32(s->baud, BAUD, OSR);
    return clock_get_hz(s->clk) / (sbr * (osr + 1));
}

#endif