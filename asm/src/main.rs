use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, BufRead, Write},
    path::Path,
    vec,
};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("Arg count is not 3");
    }
    if !args[1].ends_with(".asm") {
        panic!("Input file is not .asm file");
    }
    if !args[2].ends_with(".hack") {
        panic!("Output format should be .hack");
    }

    let input_file_path = &args[1];
    let output_file_path = &args[2];
    let lines = read_lines(input_file_path).expect("Cannot find file");

    let mut clean_lines = Vec::<String>::new();
    // strip comment and all splaces
    for line in lines.into_iter().map_while(Result::ok) {
        let s = strip_comment(line.as_str()).replace(' ', "");
        if !s.is_empty() {
            clean_lines.push(s);
        }
    }

    let mut symbol_table = HashMap::from([
        ("R0", 0),
        ("R1", 1),
        ("R2", 2),
        ("R3", 3),
        ("R4", 4),
        ("R5", 5),
        ("R6", 6),
        ("R7", 7),
        ("R8", 8),
        ("R9", 9),
        ("R10", 10),
        ("R11", 11),
        ("R12", 12),
        ("R13", 13),
        ("R14", 14),
        ("R15", 15),
        ("SCREEN", 16384),
        ("KBD", 24576),
        ("SP", 0),
        ("LCL", 1),
        ("ARG", 2),
        ("THIS", 3),
        ("THAT", 4),
    ]);

    let clean_no_label_lines = strip_asm_label_and_sym(&clean_lines, &mut symbol_table);
    let bin = compile(&clean_no_label_lines);
    let mut file = File::create(output_file_path)?;
    for line in bin {
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
    }

    return Ok(());
}

fn tables() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let comp_table = vec![
        vec![1, 0, 1, 0, 1, 0],
        vec![1, 1, 1, 1, 1, 1],
        vec![1, 1, 1, 0, 1, 0],
        vec![0, 0, 1, 1, 0, 0],
        vec![1, 1, 0, 0, 0, 0],
        vec![0, 0, 1, 1, 0, 1],
        vec![1, 1, 0, 0, 0, 1],
        vec![0, 0, 1, 1, 1, 1],
        vec![1, 1, 0, 0, 1, 1],
        vec![0, 1, 1, 1, 1, 1],
        vec![1, 1, 0, 1, 1, 1],
        vec![0, 0, 1, 1, 1, 0],
        vec![1, 1, 0, 0, 1, 0],
        vec![0, 0, 0, 0, 1, 0],
        vec![0, 1, 0, 0, 1, 1],
        vec![0, 0, 0, 1, 1, 1],
        vec![0, 0, 0, 0, 0, 0],
        vec![0, 1, 0, 1, 0, 1],
    ];
    let jmp_table = vec![
        vec![0, 0, 0],
        vec![0, 0, 1],
        vec![0, 1, 0],
        vec![0, 1, 1],
        vec![1, 0, 0],
        vec![1, 0, 1],
        vec![1, 1, 0],
        vec![1, 1, 1],
    ];

    return (comp_table, jmp_table);
}

fn map_to_binary(
    dest: Option<&str>,
    comp: Option<&str>,
    jmp: Option<&str>,
    comp_table: &[Vec<u8>],
    jmp_table: &[Vec<u8>],
) -> Vec<u8> {
    let mut cmd = vec![1u8; 3];

    let comp = comp.unwrap();
    let comp_idx;
    match comp {
        "0" => {
            comp_idx = (0, 0);
        }
        "1" => {
            comp_idx = (0, 1);
        }
        "-1" => {
            comp_idx = (0, 2);
        }
        "D" => {
            comp_idx = (0, 3);
        }
        "A" => {
            comp_idx = (0, 4);
        }
        "M" => {
            comp_idx = (1, 4);
        }
        "!D" => {
            comp_idx = (0, 5);
        }
        "!A" => {
            comp_idx = (0, 6);
        }
        "!M" => {
            comp_idx = (1, 6);
        }
        "-D" => {
            comp_idx = (0, 7);
        }
        "-A" => {
            comp_idx = (0, 8);
        }
        "-M" => {
            comp_idx = (1, 8);
        }
        "D+1" => {
            comp_idx = (0, 9);
        }
        "A+1" => {
            comp_idx = (0, 10);
        }
        "M+1" => {
            comp_idx = (1, 10);
        }
        "D-1" => {
            comp_idx = (0, 11);
        }
        "A-1" => {
            comp_idx = (0, 12);
        }
        "M-1" => {
            comp_idx = (1, 12);
        }
        "D+A" => {
            comp_idx = (0, 13);
        }
        "D+M" => {
            comp_idx = (1, 13);
        }
        "D-A" => {
            comp_idx = (0, 14);
        }
        "D-M" => {
            comp_idx = (1, 14);
        }
        "A-D" => {
            comp_idx = (0, 15);
        }
        "M-D" => {
            comp_idx = (1, 15);
        }
        "D&A" => {
            comp_idx = (0, 16);
        }
        "D&M" => {
            comp_idx = (1, 16);
        }
        "D|A" => {
            comp_idx = (0, 17);
        }
        "D|M" => {
            comp_idx = (1, 17);
        }
        wildcard => {
            panic!("comp no match: {}", wildcard)
        }
    }

    let mut dest_bits = vec![0u8; 3];
    if let Some(dest) = dest {
        for u in dest.as_bytes() {
            match u {
                b'M' => dest_bits[2] = 1,
                b'D' => dest_bits[1] = 1,
                b'A' => dest_bits[0] = 1,
                wildcard => {
                    panic!("dest no match u8: {}", wildcard)
                }
            }
        }
    }

    let jmp_idx;
    if let Some(jmp) = jmp {
        match jmp {
            "JGT" => jmp_idx = 1,
            "JEQ" => jmp_idx = 2,
            "JGE" => jmp_idx = 3,
            "JLT" => jmp_idx = 4,
            "JNE" => jmp_idx = 5,
            "JLE" => jmp_idx = 6,
            "JMP" => jmp_idx = 7,
            wildcard => {
                panic!("jmp no match: {}", wildcard)
            }
        }
    } else {
        jmp_idx = 0;
    }

    cmd.push(comp_idx.0);
    cmd.extend(&comp_table[comp_idx.1]);
    cmd.append(&mut dest_bits);
    cmd.extend(&jmp_table[jmp_idx]);
    cmd.iter_mut().for_each(|b| {
        *b += b'0';
    });
    return cmd;
}

fn compile(asm: &Vec<&str>) -> Vec<String> {
    let mut ans = Vec::with_capacity(asm.len());
    let (comp_table, dest_jmp_table) = tables();
    for line in asm {
        let bs = line.as_bytes();
        if bs[0] == b'@' {
            let t = &line[1..]
                .parse::<u16>()
                .expect("A instruction num exceeds u16");
            let mut t = format!("{:b}", t).as_bytes().to_vec();
            let patch = 16 - t.len();
            let mut tt = vec![b'0'; patch];
            tt.append(&mut t);
            ans.push(String::from_utf8(tt).unwrap());
        } else {
            let parts = line.split('=').collect::<Vec<&str>>();
            let mut dest = Option::<&str>::None;
            let comp;
            let mut jmp = Option::<&str>::None;
            if parts.len() == 2 {
                dest = Some(parts[0]);
                let parts = parts[1];
                let parts = parts.split(';').collect::<Vec<&str>>();
                if parts.len() == 2 {
                    jmp = Some(parts[1]);
                }
                comp = Some(parts[0]);
            } else {
                // no `=`
                let parts = parts[0];
                let parts = parts.split(';').collect::<Vec<&str>>();
                if parts.len() == 2 {
                    jmp = Some(parts[1]);
                }
                comp = Some(parts[0]);
            }

            ans.push(
                String::from_utf8(map_to_binary(dest, comp, jmp, &comp_table, &dest_jmp_table))
                    .unwrap(),
            );
        }
    }
    return ans;
}

fn strip_asm_label_and_sym<'a>(
    clean_lines: &'a [String],
    symbol_table: &mut HashMap<&'a str, i32>,
) -> Vec<&'a str> {
    let mut clean_no_label_lines = Vec::<&'a str>::with_capacity(clean_lines.len());
    // strip label line
    let mut line_num = 0;
    for line in clean_lines.iter() {
        match line.as_bytes()[0] {
            b'(' => {
                // label
                let sym = &line[1..(line.len() - 1)];
                symbol_table.insert(sym, line_num);
            }
            _ => {
                clean_no_label_lines.push(line);
                line_num += 1;
            }
        }
    }
    // replace line symbol with line number
    for line in clean_no_label_lines.iter_mut() {
        let bs = line.as_bytes();

        if bs[0] == b'@' {
            // A instruction
            if !(bs[1] <= b'9' && bs[1] >= b'0') {
                let sym = std::str::from_utf8(&bs[1..]).expect("Input is not utf8");
                if let Some(line_num) = symbol_table.get(sym) {
                    let mut no = line_num.to_string().into_bytes();
                    let mut instruct = "@".to_string().into_bytes();
                    instruct.append(&mut no);

                    let t = Box::leak(Box::<String>::new(
                        String::from_utf8(instruct).expect("Input is not utf8"),
                    ));
                    *line = t.as_str();
                }
            }
        }
    }
    let mut stack_ptr = 16;
    // replace stack variable with stack index
    for line in clean_no_label_lines.iter_mut() {
        let bs = line.as_bytes();
        if bs[0] == b'@' {
            // A instruction
            if !(bs[1] <= b'9' && bs[1] >= b'0') {
                let sym = std::str::from_utf8(&bs[1..]).expect("Input is not utf8");
                let mut instruct = "@".to_string().into_bytes();
                if let Some(line_num) = symbol_table.get(sym) {
                    let mut no = line_num.to_string().into_bytes();
                    instruct.append(&mut no);
                } else {
                    instruct.append(&mut stack_ptr.to_string().into_bytes());
                    symbol_table.insert(sym, stack_ptr);
                    stack_ptr += 1;
                }
                let t = Box::leak(Box::<String>::new(
                    String::from_utf8(instruct).expect("Input is not utf8"),
                ));
                *line = t.as_str();
            }
        }
    }
    return clean_no_label_lines;
}

fn strip_comment(s: &str) -> &str {
    let chrs = s.as_bytes();
    for (i, c) in chrs.iter().enumerate() {
        if *c == b'/' {
            return &s[..i];
        }
    }
    return s;
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
