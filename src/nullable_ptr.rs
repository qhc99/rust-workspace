use std::{cell::RefCell, rc::Rc, ops::Deref};

pub type Pointer<Val> = Rc<RefCell<Val>>;

#[derive(Debug)]
pub struct NullablePtr<M> {
    nullable: Option<Pointer<M>>,
}

#[allow(dead_code)]
impl<M> NullablePtr<M> {
    pub fn new(m: M) -> NullablePtr<M> {
        NullablePtr {
            nullable: Some(Rc::new(RefCell::new(m))),
        }
    }

    pub fn of(p: Pointer<M>) -> NullablePtr<M> {
        NullablePtr { nullable: Some(p) }
    }

    pub fn nullptr() -> NullablePtr<M> {
        NullablePtr { nullable: None }
    }

    pub fn unwrap(&self) -> Pointer<M> {
        self.nullable.as_ref().expect("null ptr.").clone()
    }

    pub fn is_null(&self) -> bool {
        self.nullable.is_none()
    }

    pub fn not_null(&self) -> bool {
        self.nullable.is_some()
    }
}

impl<M> Clone for NullablePtr<M> {
    fn clone(&self) -> Self {
        Self {
            nullable: self.nullable.clone(),
        }
    }
}

impl <M> Deref for NullablePtr<M> {
    type Target = Pointer<M>;

    fn deref(&self) -> &Self::Target {
        self.nullable.as_ref().expect("null ptr.")
    }
}
