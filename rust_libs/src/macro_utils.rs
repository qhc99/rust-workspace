#[macro_export]
macro_rules! vec2d {
    [$($element:expr),+] => {
        {
            let mut v = Vec::new();
            // e.g. $element = [0,1,2]
            $(v.push($element.to_vec());)*
            v
        }
    };
}

#[macro_export]
macro_rules! f_loc {
    () => {
        concat!(file!(), ",", line!(), ":", column!())
    };
}

#[macro_export]
macro_rules! f_msg {
    ($msg:expr) => {
        concat!(file!(), ",", line!(), ":", column!(), " - ", $msg)
    };
}
