use wgpu::Instance;
use winit::{event_loop::EventLoop, window::Window};

pub async fn draw_triangle(event_loop: EventLoop<()>, window: Window) {
    let size = window.inner_size();

    let instance = Instance::default();

    let surface = unsafe { instance.create_surface(&window) }.unwrap();
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            // Request an adapter which can render to our surface
            compatible_surface: Some(&surface),
        })
        .await
        .expect("Failed to find an appropriate adapter");

}