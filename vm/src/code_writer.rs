use std::{fs::File, path::PathBuf};

use std::io::Write;

pub struct CodeWriter {
    out: File,
    file_name: String,
    cond_label_num: u16,
}

impl CodeWriter {
    pub fn new(out_path: PathBuf) -> Self {
        let file_name = out_path
            .file_stem()
            .expect("output path no file or dir name")
            .to_str()
            .expect("os str cannot convert to str")
            .to_string();
        let out = File::create(out_path).expect("cannot create output file");

        CodeWriter {
            out,
            file_name,
            cond_label_num: 0,
        }
    }

    pub fn write_arithmetic(&mut self, cmd: String) {
        match cmd.as_str() {
            "add" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D+M",
                );
            }
            "sub" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=M-D",
                );
            }
            "neg" => {
                self.write(
                    "
@0
A=M-1
M=-M",
                );
            }
            "eq" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare(&"JEQ");
                self.cond_label_num += 1;
            }
            "gt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare(&"JGT");
                self.cond_label_num += 1;
            }
            "lt" => {
                self.gen_arithmetic_double_partial();
                self.gen_partial_compare(&"JLT");
                self.cond_label_num += 1;
            }
            "and" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D&M",
                )
            }
            "or" => {
                self.gen_arithmetic_double_partial();
                self.write(
                    "
M=D|M",
                );
            }
            "not" => {
                self.write(
                    "
@0
A=M-1
M=!M",
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
D;{2}
@0
A=M-1
M=0
@{0}$cond$false.{1}
0;JMP
({0}$cond$true.{1})
@0
A=M-1
M=-1
({0}$cond$false.{1})",
            self.file_name, self.cond_label_num, j
        ));
    }

    /// SP <- SP-1, D <- RAM[SP], M <- RAM[SP-1]
    fn gen_arithmetic_double_partial(&mut self) {
        self.out
            .write_all(
                "
@0
M=M-1
A=M
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
            "static" => self.write_reg_a_push(&format!("{0}.{1}", self.file_name, idx),false),
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
@{0}
D={1}
@0
A=M
M=D
@0
M=M+1",
            a, if immediate {"A"} else{"M"}
        ))
    }

    fn write_base_shift_push(&mut self, base: i16, shift: i16, indirect: bool) {
        self.write(&format!(
            "
@{0}
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
@0
M=M-1
A=M
D=M
@R13 
M=D
@{0}
D={2}
@{1}
D=D+A
@R14 
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
@0
M=M-1",
            ),
            "static" => self.write(&format!(
                "
@0
M=M-1
A=M
D=M
@{0}.{1}
M=D",
                self.file_name, idx
            )),
            "temp" => self.write_base_shift_pop(5, idx, false),
            "pointer" => self.write_base_shift_pop(3, idx, false),
            _ => {
                panic!("unknown push stack segment")
            }
        }
    }
}
