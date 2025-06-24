use std::any::Any;
use std::rc::Weak;

use typed_builder::TypedBuilder;

use super::traits::BreakpointType;

use super::stoppoint_collection::StoppointCollection;

use super::{sdb_error::SdbError, traits::StoppointTrait, types::VirtualAddress};

use super::target::Target;

pub type IdType = i32;

#[derive(TypedBuilder)]
pub struct Breakpoint {
    id: IdType,
    target: Weak<Target>,
    #[builder(default = false)]
    is_enabled: bool,
    #[builder(default = false)]
    is_hardware: bool,
    #[builder(default = false)]
    is_internal: bool,
    breakpoint_sites: StoppointCollection,
    #[builder(default = 1)]
    next_site_id: IdType,
}

impl StoppointTrait for Breakpoint {

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn breakpoint_type(&self) -> BreakpointType {
       BreakpointType::BreakPoint
    }

    fn id(&self) -> IdType {
        self.id
    }

    fn at_address(&self, addr: VirtualAddress) -> bool {
        self.breakpoint_sites.contains_address(addr)
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
        !self.breakpoint_sites.get_in_region(low, high).is_empty()
    }

    fn is_hardware(&self) -> bool {
        self.is_hardware
    }

    fn is_internal(&self) -> bool {
        self.is_internal
    }

    fn breakpoint_sites(&self) -> StoppointCollection {
        self.breakpoint_sites.clone()
    }
}
