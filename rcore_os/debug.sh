cargo build --release
# strip is not necessary for qemu version >= 7.0.0
rust-objcopy --strip-all target/riscv64gc-unknown-none-elf/release/rcore_os -O binary target/riscv64gc-unknown-none-elf/release/rcore_os.bin
qemu-system-riscv64 \
    -machine virt \
    -nographic \
    -bios ./bootloader/rustsbi-qemu.bin \
    -device loader,file=target/riscv64gc-unknown-none-elf/release/rcore_os.bin,addr=0x80200000 \
    -s -S