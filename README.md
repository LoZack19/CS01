# Cybersecurity Project

# Timeline

- Build a template for the TPM peripheral
- Implement TPM (Giovanni + Tommaso)
    - (Idea) https://chatgpt.com/share/68739b5b-0ad4-800a-9be4-929466039e64
    - Access TPM peripheral
    - TODO: Send command
- Connect TPM (Mateus)
    - wip: initialize TPM on the board
    - spotted compilation warnings
- Write firmware (Mansour)
    - wip: setup environment

## Compilation

```bash
cd CS01/qemu
./configure --enable-debug --target-list=arm-softmmu
make -j8
```
