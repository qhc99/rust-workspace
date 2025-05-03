use super::{breakpoint_site::IdType, types::VirtualAddress};

pub trait StoppointTrait {
    fn id(&self) -> IdType;

    fn at_address(&self, addr: VirtualAddress) -> bool;

    fn disable(&mut self);

    fn address(&self) -> VirtualAddress;
}
