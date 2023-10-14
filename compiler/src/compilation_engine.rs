use crate::tokens::Token;

pub trait CompilationEngine {
    fn compile(out_path: &str, tokens: Vec<Token>);

    fn compile_class(&mut self);

    fn compile_class_var_dec(&mut self);

    fn compile_sub_routine_dec(&mut self);

    fn compile_parameter_list(&mut self);

    fn compile_sub_routine_body(&mut self);

    fn compile_var_dec(&mut self);

    fn compile_statements(&mut self);

    fn compile_let(&mut self);

    fn compile_if(&mut self);

    fn compile_while(&mut self);

    fn compile_do(&mut self);

    fn compile_return(&mut self);

    fn compile_expression(&mut self);

    fn compile_term(&mut self);

    fn compile_expression_list(&mut self)->u32;
}



