#![allow(dead_code)]
#![allow(clippy::needless_return)]
use triangle::Renderer;
use wgpu::{Instance, InstanceDescriptor};
use winit::{event_loop::EventLoop, window::Window};

mod triangle;

#[tokio::main]
async fn main() {
    // Open a connection to the mini-redis address.
    let event_loop = EventLoop::new();
    let window = Window::new(&event_loop).unwrap();
    std::env::set_var("RUST_LOG", "warn");
    env_logger::init();
    let mut render = Renderer::new(event_loop, window).await;
    render.start().await;
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
