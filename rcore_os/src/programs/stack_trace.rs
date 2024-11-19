use core::arch::asm;

pub fn print_stack_trace_fp_chain() {
    println!("=== Stack trace from fp chain ===");

    unsafe {
        let mut fp: *const usize;
        asm!(
            "mv {}, fp",
            out(reg) fp,
        );

        while !fp.is_null() {
            // x86_64 architecture: return address is at fp + 1, old fp is at fp
            let return_address = *fp.sub(1);
            let old_fp = *fp.sub(2);

            println!("Return address: 0x{:016x}", return_address);
            println!("Old frame pointer: 0x{:016x}", old_fp as usize);

            fp = old_fp as *const usize;
        }
    }

    println!("=== End ===\n");
}
