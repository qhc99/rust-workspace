use super::{breakpoint_site::IdType, types::VirtualAddress};
use super::sdb_error::SdbError;

pub trait StoppointTrait {
    fn id(&self) -> IdType;

    fn at_address(&self, addr: VirtualAddress) -> bool;

    fn disable(&mut self)-> Result<(), SdbError>;

    fn address(&self) -> VirtualAddress;

    fn enable(&mut self) -> Result<(), SdbError>;
}
