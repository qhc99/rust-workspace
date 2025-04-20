use std::path::Path;

pub trait Kmp {
    /// Treat string as an array of bytes. Return the matched index of the array.
    /// Note that the returned index may not be the index of characters in UTF-8
    fn kmp_find_match_from(&self, pattern: &dyn Kmp, start_idx: usize) -> Option<usize> {
        let s = self.to_ref_u8_slice();
        let p = pattern.to_ref_u8_slice();

        if (p.is_empty()) || (s.is_empty()) {
            return None;
        }

        if p.len() == 1 {
            for (idx, c) in s.iter().enumerate() {
                if *c == p[0] {
                    return Some(idx);
                }
            }
            return None;
        }

        let next = compute_partial_match_table(p);
        todo!()
    }

    fn kmp_find_match(&self, pattern: &dyn Kmp) -> Option<usize> {
        return self.kmp_find_match_from(pattern, 0);
    }

    fn to_ref_u8_slice(&self) -> &[u8];
}

fn compute_partial_match_table(p: &[u8]) -> Vec<usize> {
    let mut next = vec![0; p.len()];
    let mut i = 1usize;
    let mut j = 0usize;

    for i in 1..p.len() {}

    return next;
}

impl Kmp for [u8] {
    fn to_ref_u8_slice(&self) -> &[u8] {
        return self;
    }
}

impl Kmp for String {
    fn to_ref_u8_slice(&self) -> &[u8] {
        return self.as_bytes();
    }
}

impl Kmp for Vec<u8> {
    fn to_ref_u8_slice(&self) -> &[u8] {
        return self;
    }
}

impl Kmp for &str {
    fn to_ref_u8_slice(&self) -> &[u8] {
        return self.as_bytes();
    }
}

impl Kmp for Path {
    fn to_ref_u8_slice(&self) -> &[u8] {
        return self.as_os_str().as_encoded_bytes();
    }
}
