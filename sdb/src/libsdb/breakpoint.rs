use std::any::Any;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicI32, Ordering};

use typed_builder::TypedBuilder;

use super::traits::BreakpointType;

use super::stoppoint_collection::StoppointCollection;

use super::{sdb_error::SdbError, traits::StoppointTrait, types::VirtualAddress};

use super::target::Target;

pub type IdType = i32;

static NEXT_ID: AtomicI32 = AtomicI32::new(0);

fn get_next_id() -> IdType {
    NEXT_ID.fetch_add(1, Ordering::SeqCst) + 1
}

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

impl Breakpoint {
    pub fn new(target: &Rc<Target>, is_hardware: bool, is_internal: bool) -> Self {
        let id = if is_internal { -1 } else { get_next_id() };
        Self {
            id,
            target: Rc::downgrade(target),
            is_enabled: false,
            is_hardware,
            is_internal,
            breakpoint_sites: StoppointCollection::default(),
            next_site_id: 1,
        }
    }
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
        self.is_enabled = false;
        for i in self.breakpoint_sites.iter() {
            i.borrow_mut().disable()?;
        }
        Ok(())
    }

    fn address(&self) -> VirtualAddress {
        unimplemented!()
    }

    fn enable(&mut self) -> Result<(), SdbError> {
        self.is_enabled = true;
        for i in self.breakpoint_sites.iter() {
            i.borrow_mut().enable()?;
        }
        Ok(())
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

pub struct FunctionBreakpoint {
    pub breakpoint: Breakpoint,
    function_name: String,
}

impl FunctionBreakpoint {
    pub fn new(
        target: &Rc<Target>,
        function_name: &str,
        is_hardware: bool, // false
        is_internal: bool, // false
    ) -> Self {
        let mut ret = Self {
            breakpoint: Breakpoint::new(target, is_hardware, is_internal),
            function_name: function_name.to_string(),
        };
        ret.resolve();
        ret
    }

    pub fn resolve(&mut self) {
        todo!()
    }

    fn function_name(&self) -> &str {
        &self.function_name
    }
}

// TODO p397
/*
namespace sdb {
class line_breakpoint : public breakpoint {
    public:
        void resolve() override;
        const std::filesystem::path file() const { return file_; }
        std::size_t line() const { return line_; }
    private:
        friend target;
        line_breakpoint(target& tgt,
                std::filesystem::path file,
                std::size_t line,
                bool is_hardware = false,
                bool is_internal = false)
                : breakpoint(tgt, is_hardware, is_internal), file_(std::move(file)), line_(line) {
            resolve();
        }
        std::filesystem::path file_;
        std::size_t line_;
    };

class address_breakpoint : public breakpoint {
    public:
        void resolve() override;
        virt_addr address() const { return address_; }
    private:
        friend target;
        address_breakpoint(
                target& tgt, virt_addr address,
                bool is_hardware = false, bool is_internal = false)
                : breakpoint(tgt, is_hardware, is_internal), address_(address) {
            resolve();
        }
        virt_addr address_;
    };
}
*/
