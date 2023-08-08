pub fn get_kth_digit(num: i32, k: i32) -> i32 {
    return (num >> k) & 1;
}

pub fn last_K_digits(num: i32, k: i32) -> i32 {
    return num & ((1 << k) - 1);
}

pub fn not_Kth_digit(num: i32, k: i32) -> i32 {
    return num ^ (1 << k);
}

pub fn set_Kth_digit_1(num: i32, k: i32) -> i32 {
    return num | (1 << k);
}

pub fn set_Kth_digit_0(num: i32, k: i32) -> i32 {
    return num & (!(1 << k));
}
