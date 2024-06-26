use wgpu_demo::Renderer;
use wgpu::{Instance, InstanceDescriptor};
use winit::{event_loop::EventLoop, window::Window};
mod wgpu_demo;

#[tokio::main]
async fn main() {
    let event_loop = EventLoop::new().unwrap();
    let mut builder = winit::window::WindowBuilder::new();
    let window = builder.build(&event_loop).unwrap();
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
