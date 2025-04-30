use std::ops::{Add, AddAssign, Sub, SubAssign};

pub type Byte64 = [u8; 8];
pub type Byte128 = [u8; 16];

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualAddress {
    addr: u64,
}

impl VirtualAddress {
    pub fn get_addr(&self) -> u64 {
        self.addr
    }
}

impl Add<i64> for VirtualAddress {
    type Output = VirtualAddress;

    fn add(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 + rhs as i128) as u64,
        }
    }
}

impl AddAssign<i64> for VirtualAddress {
    fn add_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 + rhs as i128) as u64;
    }
}

impl Sub<i64> for VirtualAddress {
    type Output = VirtualAddress;

    fn sub(self, rhs: i64) -> Self::Output {
        Self {
            addr: (self.addr as i128 - rhs as i128) as u64,
        }
    }
}

impl SubAssign<i64> for VirtualAddress {
    fn sub_assign(&mut self, rhs: i64) {
        self.addr = (self.addr as i128 - rhs as i128) as u64;
    }
}
