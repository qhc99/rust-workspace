use std::collections::HashMap;

#[derive(Clone, Eq, PartialEq)]
pub enum VarType {
    Static,
    Field,
    Arg,
    Var,
    None,
}

pub struct SymbolTable {
    class_table: HashMap<String, (String, VarType, u32)>,
    static_count: u32,
    sub_routine_table: HashMap<String, (String, VarType, u32)>,
    var_count: u32,
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable {
            class_table: HashMap::new(),
            static_count: 0,
            sub_routine_table: HashMap::new(),
            var_count: 0,
        }
    }

    pub fn start_subroutine(&mut self) {
        self.sub_routine_table.clear();
        self.var_count = 0;
    }

    pub fn define(&mut self, name: &str, tp: &str, kind: &VarType) {
        match kind {
            VarType::Static | VarType::Field => {
                self.class_table.insert(
                    name.to_string(),
                    (tp.to_string(), kind.clone(), self.var_count(&kind) + 1),
                );
                if *kind == VarType::Static {
                    self.static_count += 1;
                }
            }
            VarType::Arg | VarType::Var => {
                self.sub_routine_table.insert(
                    name.to_string(),
                    (tp.to_string(), kind.clone(), self.var_count(&kind) + 1),
                );
                if *kind == VarType::Var {
                    self.var_count += 1;
                }
            }
            VarType::None => {
                panic!()
            }
        }
    }

    pub fn var_count(&self, kind: &VarType) -> u32 {
        match kind {
            VarType::Static => self.static_count,
            VarType::Field => self.class_table.len() as u32 - self.static_count,
            VarType::Arg => self.sub_routine_table.len() as u32 - self.var_count,
            VarType::Var => self.var_count,
            VarType::None => {
                panic!()
            }
        }
    }
    pub fn kind_of(&self, name: &str) -> &VarType {
        &self.row_of(name).1
    }

    pub fn type_of(&self, name: &str) -> &str {
        &self.row_of(name).0
    }

    pub fn index_of(&self, name: &str) -> u32 {
        self.row_of(name).2
    }

    pub fn has_id(&self, name: &str) -> bool {
        return self.class_table.contains_key(name) || self.sub_routine_table.contains_key(name);
    }

    fn row_of(&self, name: &str) -> &(String, VarType, u32) {
        if self.sub_routine_table.contains_key(name) {
            self.sub_routine_table.get(name).unwrap()
        } else if self.class_table.contains_key(name) {
            self.class_table.get(name).unwrap()
        } else {
            panic!()
        }
    }
}
