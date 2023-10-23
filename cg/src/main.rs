#![allow(dead_code)]
#![allow(clippy::needless_return)]
use std::io;

use wgpu::{Instance, InstanceDescriptor};
use winit::{event_loop::EventLoop, window::Window};

mod triangle;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Open a connection to the mini-redis address.
    let event_loop = EventLoop::new();
    let window = Window::new(&event_loop).unwrap();
    env_logger::init();
    triangle::draw_triangle(event_loop, window).await;
    Ok(())
}



fn print_backends() {
    // Create a new instance of wgpu
    let instance = Instance::new(InstanceDescriptor::default());

    // Retrieve all the available adapters (GPUs) on the system
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());

    // Go through each of the adapters and print out its information
    for adapter in adapters {
        let info = adapter.get_info();
        println!("{:?}", info);
        // You can check 'info.name', 'info.vendor', 'info.device' etc.
        // to identify the GPUs. You might be able to recognize the NVIDIA
        // GPU by its name or vendor ID.
    }
}
