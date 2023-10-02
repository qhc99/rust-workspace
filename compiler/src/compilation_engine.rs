pub trait CompilationEngine {
    fn new() -> Self;

    fn compile_class(&self);

    fn compile_class_var_dec(&self);

    fn compile_sub_routine_dec(&self);

    fn compile_parameter_list(&self);

    fn compile_sub_routine_body(&self);

    fn compile_var_dec(&self);

    fn compile_var_statements(&self);

    fn compile_let(&self);

    fn compile_if(&self);

    fn compile_while(&self);

    fn compile_do(&self);

    fn compile_return(&self);

    fn compile_expression(&self);

    fn compile_term(&self);

    fn compile_expression_list(&self);
}



