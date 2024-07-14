use std::{fs::File, io::Write, path::PathBuf};

pub struct CodeWriter {
    out: File,
    input_file_name: String,
    cond_label_num: u16,
    if_goto_num: u16,
    func_call_ret_num: u16,
    func_clean_lcl_num: u16,
}

impl CodeWriter {
    pub fn new(out_path: &PathBuf) -> Self {
        let out = File::create(out_path).expect("cannot create output file");

        CodeWriter {
            out,
            input_file_name: "".to_string(),
            cond_label_num: 0,
            if_goto_num: 0,
            func_call_ret_num: 0,
            func_clean_lcl_num: 0,
        }
    }

    pub fn reset_input_metadata(&mut self, in_name: &str) {
        self.input_file_name = in_name.to_string();
        self.cond_label_num = 0;
        self.if_goto_num = 0;
        self.func_call_ret_num = 0;
        self.func_clean_lcl_num = 0;
    }

    pub fn write_arithmetic(&mut self, cmd: String) {
        match cmd.as_str() {
            "add" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D+M // add",
                );
            }
            "sub" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=M-D // sub",
                );
            }
            "neg" => {
                self.write(
                    "
@0 // neg
A=M-1
M=-M",
                );
            }
            "eq" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JEQ");
            }
            "gt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JGT");
            }
            "lt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare("JLT");
            }
            "and" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D&M // and",
                )
            }
            "or" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D|M // or",
                );
            }
            "not" => {
                self.write(
                    "
@0
A=M-1
M=!M // not",
                );
            }
            other => {
                panic!("unmatched arithmetic cmd: {}", other)
            }
        }
    }

    // write string with \n at head and after every line except the last line
    fn write(&mut self, data: &str) {
        self.out
            .write_all(data.as_bytes())
            .expect("cannot write to output file");
    }

    fn gen_partial_compare(&mut self, j: &str) {
        self.write(&format!(
            "
D=M-D
@{0}$cond$true.{1}
D;{2} // {2} to true
@0
A=M-1
M=0
@{0}$cond$false.{1}
0;JMP // JMP to false
({0}$cond$true.{1})
@0
A=M-1
M=-1
({0}$cond$false.{1})",
            self.input_file_name, self.cond_label_num, j
        ));
        self.cond_label_num += 1;
    }

    /// SP <- SP-1, A <- SP-1 D <- RAM[SP], A <- SP-1
    fn gen_arithmetic_double_partial(&mut self) {
        self.out
            .write_all(
                "
@0 // arithmetic double operator
AM=M-1
D=M
A=A-1"
                    .as_bytes(),
            )
            .unwrap();
    }

    pub fn write_push(&mut self, seg: &str, idx: i16) {
        match seg {
            "local" => self.write_base_shift_push(1, idx, true),
            "argument" => self.write_base_shift_push(2, idx, true),
            "this" => self.write_base_shift_push(3, idx, true),
            "that" => self.write_base_shift_push(4, idx, true),
            "constant" => self.write_reg_a_push(&idx.to_string(), true),
            "static" => {
                self.write_reg_a_push(&format!("{0}.{1}", self.input_file_name, idx), false)
            }
            "temp" => self.write_base_shift_push(5, idx, false),
            "pointer" => self.write_base_shift_push(3, idx, false),
            _ => {
                panic!("unknown push stack segment")
            }
        }
    }

    fn write_reg_a_push(&mut self, a: &str, immediate: bool) {
        self.write(&format!(
            "
@{0} // push reg {a}, {immediate}
D={1}
@0
A=M
M=D
@0
M=M+1",
            a,
            if immediate { "A" } else { "M" }
        ))
    }

    fn write_base_shift_push(&mut self, base: i16, shift: i16, indirect: bool) {
        self.write(&format!(
            "
@{0} // push {base} {shift}, {2}
D={2}
@{1}
A=D+A
D=M
@0
A=M
M=D
@0
M=M+1",
            base,
            shift,
            if indirect { "M" } else { "A" }
        ))
    }

    fn write_base_shift_pop(&mut self, base: i16, shift: i16, indirect: bool) {
        self.write(&format!(
            "
@0 // pop {base} {shift}, {2}
AM=M-1
D=M
@R13 // RAM[R13] = val
M=D
@{0}
D={2}
@{1}
D=D+A
@R14 // RAM[R14] = addr
M=D
@R13
D=M
@R14
A=M
M=D",
            base,
            shift,
            if indirect { "M" } else { "A" }
        ))
    }

    pub fn write_pop(&mut self, seg: &str, idx: i16) {
        match seg {
            "local" => self.write_base_shift_pop(1, idx, true),
            "argument" => self.write_base_shift_pop(2, idx, true),
            "this" => self.write_base_shift_pop(3, idx, true),
            "that" => self.write_base_shift_pop(4, idx, true),
            "constant" => self.write(
                "
@0 // pop constant
M=M-1",
            ),
            "static" => self.write(&format!(
                "
@0 // pop static 
AM=M-1
D=M
@{0}.{1} // var name
M=D",
                self.input_file_name, idx
            )),
            "temp" => self.write_base_shift_pop(5, idx, false),
            "pointer" => self.write_base_shift_pop(3, idx, false),
            _ => {
                panic!("unknown push stack segment")
            }
        }
    }

    pub fn write_label(&mut self, arg1: &str) {
        self.write(&format!(
            "
({})",
            arg1
        ))
    }

    pub fn write_goto(&mut self, arg1: &str) {
        self.write(&format!(
            "
@{} // goto
0;JMP",
            arg1
        ))
    }

    pub fn write_if_goto(&mut self, arg1: &str) {
        self.write(&format!(
            "
@0 // if-goto {arg1}
AM=M-1
D=M
@{0}$if-goto$false.{1}
D;JEQ
@{2}
0;JMP
({0}$if-goto$false.{1})",
            self.input_file_name, self.if_goto_num, arg1
        ));
        self.if_goto_num += 1;
    }

    pub fn write_function(&mut self, func_name: &str, lcl: i16) {
        self.write(&format!(
            "
({0}$entry) // function {0} {1}
@0
D=M
@1
M=D // load lcl
@{1}
D=D+A
@R13
M=D // RAM[R13] = stop SP
({2}$clear-lcl-loop.{3})
@R13
D=M
@0
D=D-M
@{2}$clear-lcl-stop.{3}
D;JEQ 
@0
A=M
M=0
@0
M=M+1
@{2}$clear-lcl-loop.{3}
0;JMP
({2}$clear-lcl-stop.{3})",
            func_name, lcl, self.input_file_name, self.func_clean_lcl_num
        ));
        self.func_clean_lcl_num += 1;
    }

    pub fn write_call(&mut self, func_name: &str, arg: i16) {
        self.write(&format!(
            "
@0 // call {func_name} {arg}
D=M
@{0} // arg num
D=D-A
@R13
M=D // wait to load arg
@{2}$ret.{3}
D=A
@0
A=M
M=D // save return jump line
@0
M=M+1
@1
D=M
@0
A=M
M=D // save LCL
@0
M=M+1
@2
D=M
@0
A=M
M=D // save arg 
@0
M=M+1
@3
D=M
@0
A=M
M=D // save this
@0
M=M+1
@4
D=M
@0
A=M
M=D // save that
@0
M=M+1
@R13
D=M
@2
M=D // load arg
@{1}$entry
0;JMP
({2}$ret.{3})",
            arg, func_name, self.input_file_name, self.func_call_ret_num
        ));
        self.func_call_ret_num += 1;
    }

    pub fn write_return(&mut self) {
        self.write(
            "
@0 // return
AM=M-1
D=M
@R13
M=D // RAM[R13] = ret
@1
D=M-1
@0
M=D // SP = LCL-1
@0
A=M
D=M
@4
M=D // reload that
@0
AM=M-1
D=M 
@3
M=D // reload this
@0
M=M-1
@2
D=M
@R14
M=D // RAM[R14] = arg
@0
A=M
D=M
@2
M=D // reload arg
@0
AM=M-1
D=M
@1
M=D // reload lcl
@0
A=M-1
D=M
@R15
M=D // RAM[R15] = jump
@R14
D=M
@0
M=D // reload stack base
@R13
D=M
@0
A=M
M=D // set return value
@0
M=M+1
@R15
A=M
0;JMP // return jump",
        )
    }

    pub fn write_sys_init(&mut self) {
        self.write(
            "
@256
D=A
@0
M=D
@11111
D=A
@1
M=D
@22222
D=A
@2
M=D
@33333
D=A
@3
M=D
@44444
D=A
@4
M=D
",
        );
        self.write_call("Sys.init", 0);
    }
}
