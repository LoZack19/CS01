#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "exec/address-spaces.h"
#include "target/arm/cpu.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/arm/boot.h"

#define ITCM_SIZE (64 * KiB)
#define DTCM_SIZE (128 * KiB)
#define FLASH_BLOCK_2048K (2048 * KiB)
#define FLASH_BLOCK_1024K (1024 * KiB)
#define FLASH_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_512K (512 * KiB)
#define SRAM_BLOCK_384K (384 * KiB)
#define SRAM_BLOCK_256K (256 * KiB)
#define SRAM_BLOCK_160K (160 * KiB)

typedef struct MyBoardState {
    MachineState parent_obj;
    
    // Only keep implemented memory regions
    MemoryRegion *flash_program;
    MemoryRegion *flash_data;
    MemoryRegion *sram[4];
} MyBoardState;

#define TYPE_MYBOARD_MACHINE "myboard"
#define MYBOARD(obj) \
    OBJECT_CHECK(MyBoardState, (obj), TYPE_MYBOARD_MACHINE)

static void create_program_flash(MyBoardState *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // Program flash is divided into PFC0 and PFC1 blocks
    s->flash_program = g_new(MemoryRegion, 1);
    memory_region_init_rom(s->flash_program, NULL, "program_flash", 
                          12 * FLASH_BLOCK_1024K, &error_fatal);  // Total 12MB
    memory_region_add_subregion(sys_mem, 0x00400000, s->flash_program);
}

static void create_data_flash(MyBoardState *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    s->flash_data = g_new(MemoryRegion, 1);
    memory_region_init_rom(s->flash_data, NULL, "data_flash", 
                          256 * KiB, &error_fatal);
    memory_region_add_subregion(sys_mem, 0x10000000, s->flash_data);
}

static void create_sram(MyBoardState *s)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // SRAM regions with correct sizes from memory map
    const struct {
        hwaddr base;
        size_t size;
    } sram_regions[] = {
        { 0x20400000, SRAM_BLOCK_512K }, // SRAM0
        { 0x20480000, SRAM_BLOCK_512K }, // SRAM1
        { 0x20500000, SRAM_BLOCK_512K }, // SRAM2
        { 0x20580000, SRAM_BLOCK_384K }, // SRAM3
    };
    
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sram_%d", i);
        
        s->sram[i] = g_new(MemoryRegion, 1);
        memory_region_init_ram(s->sram[i], NULL, name, sram_regions[i].size, &error_fatal);
        memory_region_add_subregion(sys_mem, sram_regions[i].base, s->sram[i]);
    }
}

static void create_unimplemented_regions(void)
{
    MemoryRegion *sys_mem = get_system_memory();
    
    // ITCM regions (4 x 64KB at same address)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "itcm_%d", i);
        MemoryRegion *itcm = g_new(MemoryRegion, 1);
        memory_region_init_io(itcm, NULL, NULL, NULL, name, ITCM_SIZE);
        memory_region_add_subregion_overlap(sys_mem, 0x00000000, itcm, i);
    }
    
    // ITCM backdoor regions (4 x 64KB at different addresses)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "itcm_%d_backdoor", i);
        MemoryRegion *itcm_backdoor = g_new(MemoryRegion, 1);
        memory_region_init_io(itcm_backdoor, NULL, NULL, NULL, name, ITCM_SIZE);
        memory_region_add_subregion(sys_mem, 0x11000000 + (i * 0x400000), itcm_backdoor);
    }
    
    // DTCM regions (4 x 128KB at same address)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "dtcm_%d", i);
        MemoryRegion *dtcm = g_new(MemoryRegion, 1);
        memory_region_init_io(dtcm, NULL, NULL, NULL, name, DTCM_SIZE);
        memory_region_add_subregion_overlap(sys_mem, 0x20000000, dtcm, i);
    }
    
    // DTCM backdoor regions (4 x 128KB at different addresses)
    for (int i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "dtcm_%d_backdoor", i);
        MemoryRegion *dtcm_backdoor = g_new(MemoryRegion, 1);
        memory_region_init_io(dtcm_backdoor, NULL, NULL, NULL, name, DTCM_SIZE);
        memory_region_add_subregion(sys_mem, 0x21000000 + (i * 0x400000), dtcm_backdoor);
    }
    
    // UTEST region (8KB)
    MemoryRegion *utest = g_new(MemoryRegion, 1);
    memory_region_init_io(utest, NULL, NULL, NULL, "utest", 8 * KiB);
    memory_region_add_subregion(sys_mem, 0x1B000000, utest);
    
    // AIPS regions
    MemoryRegion *aips0 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips0, NULL, NULL, NULL, "aips0", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40000000, aips0);

    MemoryRegion *aips1 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips1, NULL, NULL, NULL, "aips1", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40200000, aips1);

    MemoryRegion *aips2 = g_new(MemoryRegion, 1);
    memory_region_init_io(aips2, NULL, NULL, NULL, "aips2", 2 * MiB);
    memory_region_add_subregion(sys_mem, 0x40400000, aips2);

    // Additional peripheral regions
    MemoryRegion *aes = g_new(MemoryRegion, 1);
    memory_region_init_io(aes, NULL, NULL, NULL, "aes_accel", 1 * KiB);
    memory_region_add_subregion(sys_mem, 0x44000000, aes);

    MemoryRegion *qspi_rx = g_new(MemoryRegion, 1);
    memory_region_init_io(qspi_rx, NULL, NULL, NULL, "qspi_rx", 1 * KiB);
    memory_region_add_subregion(sys_mem, 0x67000000, qspi_rx);

    MemoryRegion *qspi_ahb = g_new(MemoryRegion, 1);
    memory_region_init_io(qspi_ahb, NULL, NULL, NULL, "qspi_ahb", 128 * MiB);
    memory_region_add_subregion(sys_mem, 0x68000000, qspi_ahb);

    MemoryRegion *ppb = g_new(MemoryRegion, 1);
    memory_region_init_io(ppb, NULL, NULL, NULL, "ppb", 1 * MiB);
    memory_region_add_subregion(sys_mem, 0xE0000000, ppb);
}

static void myboard_init(MachineState *machine)
{
    MyBoardState *s = MYBOARD(machine);

    // Initialize implemented memory regions
    create_program_flash(s);
    create_data_flash(s);
    create_sram(s);
    
    // Create all unimplemented device regions
    create_unimplemented_regions();

    // Initialize CPU
    const char *cpu_type = ARM_CPU_TYPE_NAME("cortex-m7");
    ARMCPU *cpu = ARM_CPU(cpu_create(cpu_type));
    if (!cpu) {
        error_report("Failed to create CPU");
        exit(1);
    }

    // Set CPU reset vector
    cpu->env.regs[15] = 0x00400000; // Program flash start
}

static void myboard_machine_init(MachineClass *mc)
{
    mc->desc = "Custom Board with Cortex-M7";
    mc->init = myboard_init;
    mc->default_ram_size = 2 * GiB; // Maximum addressable space
}

DEFINE_MACHINE("myboard", myboard_machine_init)