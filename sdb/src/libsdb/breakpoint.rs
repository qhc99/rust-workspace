use std::rc::Weak;

use typed_builder::TypedBuilder;

use super::{sdb_error::SdbError, traits::StoppointTrait, types::VirtualAddress};

use super::target::Target;

pub type IdType = i32;

#[derive(Debug, TypedBuilder)]
pub struct Breakpoint {
    id: IdType,
    target: Weak<Target>,
    #[builder(default = false)]
    is_enabled: bool,
    #[builder(default = false)]
    is_hardware: bool,
    #[builder(default = false)]
    is_internal: bool,
    // breakpoint_sites: Vec<Rc<BreakpointSite>>,
    #[builder(default = 1)]
    next_site_id: IdType,
}

impl StoppointTrait for Breakpoint {
    fn id(&self) -> IdType {
        self.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        unimplemented!()
    }

    fn disable(&mut self) -> Result<(), SdbError> {
        unimplemented!()
    }

    fn address(&self) -> VirtualAddress {
        unimplemented!()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        unimplemented!()
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn in_range(&self, low: VirtualAddress, high: VirtualAddress) -> bool {
        unimplemented!()
    }

    fn is_hardware(&self) -> bool {
        self.is_hardware
    }

    fn is_internal(&self) -> bool {
        self.is_internal
    }

    fn breakpoint_sites(&self) /* TODO return type */
    {
        todo!()
    }
}
