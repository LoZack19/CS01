# Cybersecurity Project

# Timeline

- Build a template for the TPM peripheral
- Implement TPM (Giovanni + Tommaso)
    - (Idea) https://chatgpt.com/share/68739b5b-0ad4-800a-9be4-929466039e64
    - Implement basic types
    - Access TPM peripheral
    - Implement state transitions
        - TODO: Log state transitions
    - Unmarshall command and marshal response
        - TODO: Separate into its own layer
    - Dispatch command
    - Execute command
        - GetRandom
- Connect TPM (Mateus)
    - wip: initialize TPM on the board
    - spotted compilation warnings
- Write firmware (Mansour)
    - Setup environment
    - Write test firmware for GetRandom

## Compilation

```bash
cd ./qemu
./configure --enable-debug --target-list=arm-softmmu
make -j8
```

## Running and debugging

### Running qemu

```bash
./build/qemu-system-arm -kernel ../firmware/bin/tpm_test.elf -machine s32k3x8evb-q289 -nographic -d guest_errors -serial none -serial none -serial none -serial mon:stdio
```

### Debugging qemu

```bash
gdb ./build/qemu-system-arm
```

```gdb
(gdb) run -kernel ../firmware/bin/tpm_test.elf -machine s32k3x8evb-q289 -nographic -d guest_errors -serial none -serial none -serial none -serial mon:stdio
```

### Debugging firmware

- **qemu terminal**

```bash
./build/qemu-system-arm -kernel ../firmware/bin/tpm_test.elf -machine s32k3x8evb-q289 -nographic -d guest_errors -serial none -serial none -serial none -serial mon:stdio -s -S
```

- **gdb terminal**

```bash
cd ./firmware/bin/
gdb-multiarch -q
```

```gdb
(gdb) file tpm_test.elf
(gdb) target remote localhost:1234
```