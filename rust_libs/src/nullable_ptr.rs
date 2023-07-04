use std::{cell::RefCell, ops::Deref, rc::Rc};

pub type RcRefCell<Val> = Rc<RefCell<Val>>;

#[derive(Debug)]
pub struct NullablePtr<M> {
    nullable: Option<RcRefCell<M>>,
}

#[allow(dead_code)]
impl<M> NullablePtr<M> {
    pub fn new(m: M) -> NullablePtr<M> {
        NullablePtr {
            nullable: Some(Rc::new(RefCell::new(m))),
        }
    }

    pub fn of(p: RcRefCell<M>) -> NullablePtr<M> {
        NullablePtr { nullable: Some(p) }
    }

    pub fn nullptr() -> NullablePtr<M> {
        NullablePtr { nullable: None }
    }

    /// Prefer unwrap_ref. Use unwrap to add extra clone when borrow checker reports errors 
    /// (e.g. error[E0716]: temporary value dropped while borrowed).
    pub fn unwrap(&self) -> RcRefCell<M> {
        self.nullable.as_ref().expect("null ptr.").clone()
    }

    /// Get Rc<Refcell<T>> with possible runtime nullptr error
    pub fn unwrap_ref(&self) -> &RcRefCell<M> {
        self.nullable.as_ref().expect("null ptr.")
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

impl<M> Deref for NullablePtr<M> {
    type Target = RcRefCell<M>;

    fn deref(&self) -> &Self::Target {
        self.nullable.as_ref().expect("null ptr.")
    }
}
