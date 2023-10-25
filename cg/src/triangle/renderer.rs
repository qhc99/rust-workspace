use std::borrow::Cow;

use wgpu::{
    Adapter, BindGroup, Buffer, Device, Instance, Queue, RenderPipeline, Surface, TextureFormat,
};
use winit::{event_loop::EventLoop, window::Window};

use crate::triangle::triangle_mesh::init_buffer_data;

pub async fn new(event_loop: &EventLoop<()>, window: &Window) {
    let (instance, surface, adapter, device, queue, format) = setup_device(&window).await;
    let (buffer, buffer_layout) = init_buffer_data(&device);
    let (buffer, bind_group, render_pipeline) = make_pipeline(
        &device,
        &format,
        Cow::Borrowed(include_str!("triangle.wgsl")),
    );
}

/// **Data structures relationships:**
///
/// - Instance -> Surface
///
/// - (Instance, Surface) -> Adapter
///
/// - Adapter -> (Device, Queue)
///
/// - (Surface, Adapter) -> TextureFormat
async fn setup_device(
    window: &Window,
) -> (Instance, Surface, Adapter, Device, Queue, TextureFormat) {
    let instance = Instance::default();
    let surface = unsafe { instance.create_surface(window) }.unwrap();
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            // Request an adapter which can render to our surface
            compatible_surface: Some(&surface),
        })
        .await
        .expect("Failed to find an appropriate adapter");

    let (device, queue) = adapter
        .request_device(
            &wgpu::DeviceDescriptor {
                label: Some("device-for-triangle"),
                features: wgpu::Features::empty(),
                // Make sure we use the texture resolution limits from the adapter, so we can support images the size of the swapchain.
                limits: wgpu::Limits::downlevel_webgl2_defaults()
                    .using_resolution(adapter.limits()),
            },
            None,
        )
        .await
        .expect("Failed to create device");

    let swapchain_capabilities = surface.get_capabilities(&adapter);
    let format = swapchain_capabilities.formats[0];

    return (instance, surface, adapter, device, queue, format);
}

fn make_pipeline(
    device: &Device,
    format: &TextureFormat,
    shader_path: Cow<str>,
) -> (Buffer, BindGroup, RenderPipeline) {
    let uniform_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("storage-buffer-for-triangle"),
        size: 64 * 3,
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[wgpu::BindGroupLayoutEntry {
            binding: 0,
            visibility: wgpu::ShaderStages::VERTEX,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Uniform,
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }],
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("bind-group-triangle"),
        layout: &bind_group_layout,
        entries: &[wgpu::BindGroupEntry {
            binding: 0,
            resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                buffer: &uniform_buffer,
                offset: 0,
                size: None,
            }),
        }],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: None,
        source: wgpu::ShaderSource::Wgsl(shader_path),
    });

    let render_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
        label: Some("render-pipeline-triangle"),
        layout: Some(&pipeline_layout),
        vertex: wgpu::VertexState {
            module: &shader,
            entry_point: "vs_main",
            buffers: &[], // TODO buffer
        },
        fragment: Some(wgpu::FragmentState {
            module: &shader,
            entry_point: "fs_main",
            targets: &[Some(format.to_owned().into())],
        }),
        primitive: wgpu::PrimitiveState {
            topology: wgpu::PrimitiveTopology::TriangleList,
            ..wgpu::PrimitiveState::default()
        },
        depth_stencil: None,
        multisample: wgpu::MultisampleState::default(),
        multiview: None,
    });

    return (uniform_buffer, bind_group, render_pipeline);
}

fn render(
    mut t: f32,
    window: &Window,
    device: &Device,
    queue: &Queue,
    adapter: Adapter,
    buffer: &Buffer,
    event_loop: &EventLoop<()>,
    surface: &Surface,
    texture_format: TextureFormat,
) {
    let size = window.inner_size();
    let projection =
        glam::Mat4::perspective_rh_gl(std::f32::consts::PI / 4., 800. / 600., 0.1, 10.);

    let view = glam::Mat4::look_to_rh(
        glam::Vec3 {
            x: -2.,
            y: 0.,
            z: 2.,
        },
        glam::Vec3 {
            x: 0.,
            y: 0.,
            z: 0.,
        },
        glam::Vec3 {
            x: 0.,
            y: 0.,
            z: 1.,
        },
    );

    let command_encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());

    if t > 2.0 * 3.1415 {
        t -= 2.0 * 3.1415;
    }

    let rotate = glam::Mat4::from_rotation_z(t);

    queue.write_buffer(buffer, 0, bytemuck::cast_slice(rotate.as_ref()));
    queue.write_buffer(buffer, 64, bytemuck::cast_slice(view.as_ref()));
    queue.write_buffer(buffer, 128, bytemuck::cast_slice(projection.as_ref()));

    let swapchain_capabilities = surface.get_capabilities(&adapter);
    let mut config = wgpu::SurfaceConfiguration {
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
        format: texture_format,
        width: size.width,
        height: size.height,
        present_mode: wgpu::PresentMode::Fifo,
        alpha_mode: swapchain_capabilities.alpha_modes[0],
        view_formats: vec![],
    };

    surface.configure(&device, &config);
}
