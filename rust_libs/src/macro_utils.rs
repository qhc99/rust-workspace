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