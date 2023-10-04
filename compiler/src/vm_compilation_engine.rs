use crate::compilation_engine::CompilationEngine;

pub struct VmCompilationEngine{

}

impl CompilationEngine for VmCompilationEngine {
    fn start(out_path: &str, tokens: Vec<crate::tokens::Token>) {
        todo!()
    }

    fn compile_class(&mut self) {
        todo!()
    }

    fn compile_class_var_dec(&mut self) {
        todo!()
    }

    fn compile_sub_routine_dec(&mut self) {
        todo!()
    }

    fn compile_parameter_list(&mut self) {
        todo!()
    }

    fn compile_sub_routine_body(&mut self) {
        todo!()
    }

    fn compile_var_dec(&mut self) {
        todo!()
    }

    fn compile_statements(&mut self) {
        todo!()
    }

    fn compile_let(&mut self) {
        todo!()
    }

    fn compile_if(&mut self) {
        todo!()
    }

    fn compile_while(&mut self) {
        todo!()
    }

    fn compile_do(&mut self) {
        todo!()
    }

    fn compile_return(&mut self) {
        todo!()
    }

    fn compile_expression(&mut self) {
        todo!()
    }

    fn compile_term(&mut self) {
        todo!()
    }

    fn compile_expression_list(&mut self) {
        todo!()
    }
}