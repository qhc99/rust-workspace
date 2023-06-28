// use std::{
//     cell::{RefCell, RefMut, Ref},
//     rc::Rc,
// };

// pub type Pointer<Val> = Rc<RefCell<Val>>;

// pub fn new_rc_refcell<V>(v: V) -> Pointer<V> {
//     Rc::new(RefCell::new(v))
// }

// #[derive(Debug)]
// pub struct NullablePtr<M> {
//     nullable: Option<Pointer<M>>,
// }

// impl<M> NullablePtr<M> {
//     pub fn nullptr<T>() -> NullablePtr<T> {
//         NullablePtr { nullable: None }
//     }

//     pub fn new_from_data(m: M) -> NullablePtr<M> {
//         NullablePtr { nullable: Some(new_rc_refcell(m)) }
//     }

//     pub fn new_from_ptr(p: &Pointer<M>) -> NullablePtr<M> {
//         NullablePtr { nullable: Some(p.clone()) }
//     }

//     pub fn borrow_mut(&self) -> RefMut<'_, M> {
//         self.nullable.as_ref().unwrap().borrow_mut()
//     }

//     pub fn borrow(&self) -> Ref<'_, M> {
//         self.nullable.as_ref().unwrap().borrow()
//     }

//     pub fn unwrap_rc(&self) -> &Rc<RefCell<M>> {
//         self.nullable.as_ref().unwrap()
//     }

//     pub fn unwrap_refcell(&self) -> &RefCell<M> {
//         self.nullable.as_ref().unwrap()
//     }

//     pub fn not_null(&self)->bool{
//         self.nullable.is_some()
//     }

//     pub fn is_null(&self)->bool{
//         self.nullable.is_none()
//     }
// }

// impl<M> Clone for NullablePtr<M>{
//     fn clone(&self) -> Self {
//         Self { nullable: self.nullable.clone() }
//     }
// }
