pub struct Solution {}

impl Solution {
    /// 401
    pub fn read_binary_watch(turned_on: i32) -> Vec<String> {
        let mut ret = Vec::with_capacity(256);
        Solution::read_binary_watch_visit(turned_on, 0, &mut ret, 0);
        ret
    }

    pub fn read_binary_watch_visit(on: i32, state: u16, ret: &mut Vec<String>, start: i32) {
        if on == 0 {
            let m = state & 0b111111;
            let h = (state >> 6) & 0b1111;
            if m <= 59 && h <= 11 {
                ret.push(format!("{h}:{m:02}"));
            }
            return;
        }

        for i in start..10 {
            if 10 - i >= on {
                Solution::read_binary_watch_visit(on - 1, state | (0b1 << i), ret, i + 1);
            }
        }
    }
}
