use std::f32;

/// Applies the Sobel operator to a grayscale image.
///
/// # Arguments
///
/// * `data` - A slice of `u8` representing the input grayscale image data.
/// * `output` - A mutable slice of `f32` where the output will be stored.
/// * `rows` - The number of rows in the image.
/// * `cols` - The number of columns in the image.
///
/// # Panics
///
/// This function will panic if the length of `data` or `output` is less than `rows * cols`.
#[no_mangle]
pub extern "C" fn sobel(data: &[u8], output: &mut [f32], rows: usize, cols: usize) {
    // Iterate over each pixel, skipping the border pixels
    for r in 1..rows - 1 {
        for c in 1..cols - 1 {
            // Calculate Gx using the Sobel kernel for the x-direction
            let gx = -(data[(r - 1) * cols + (c - 1)] as i32)
                + data[(r - 1) * cols + (c + 1)] as i32
                + (-2 * data[r * cols + (c - 1)] as i32)
                + (2 * data[r * cols + (c + 1)] as i32)
                + -(data[(r + 1) * cols + (c - 1)] as i32)
                + data[(r + 1) * cols + (c + 1)] as i32;

            // Calculate Gy using the Sobel kernel for the y-direction
            let gy = -(data[(r - 1) * cols + (c - 1)] as i32)
                - 2 * (data[(r - 1) * cols + c] as i32)
                - (data[(r - 1) * cols + (c + 1)] as i32)
                + data[(r + 1) * cols + (c - 1)] as i32
                + 2 * (data[(r + 1) * cols + c] as i32)
                + data[(r + 1) * cols + (c + 1)] as i32;

            // Compute the gradient magnitude
            let magnitude = ((gx as f32) * (gx as f32) + (gy as f32) * (gy as f32)).sqrt();

            // Store the result in the output slice
            output[r * cols + c] = magnitude;
        }
    }
}

pub fn main() {}
