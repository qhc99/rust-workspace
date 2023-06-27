use std::{rc::Rc, cell::{RefCell, RefMut, Ref}, ops::Deref};

pub type Pointer<Val> = Rc<RefCell<Val>>;
pub type NullablePtr<Val> = Option<Pointer<Val>>;

trait PtrMutRef {
    fn mut_ref_of_ptr<Val>(&self)-> RefMut<'_, Val>;
}


pub fn create_nullable_ptr<Val>(v: Val) -> NullablePtr<Val> {
    Some(Rc::new(RefCell::new(v)))
}

pub fn mut_ref_data<Val>(p: &Pointer<Val>) -> RefMut<'_, Val> {
    p.deref().borrow_mut()
}

pub fn ref_data<Val>(p: &Pointer<Val>) -> Ref<'_, Val> {
    p.deref().borrow()
}

pub fn unwrap_copy_ptr<Val>(p: &NullablePtr<Val>) -> Pointer<Val> {
    p.as_ref().unwrap().clone()
}


