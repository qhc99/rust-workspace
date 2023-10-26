use std::borrow::Cow;

use wgpu::{
    Adapter, BindGroup, Buffer, Device, Instance, Queue, RenderPipeline, Surface, TextureFormat,
};
use winit::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::Window,
};

use super::triangle_mesh::TriangleMesh;

pub struct Renderer {
    event_loop: Option<EventLoop<()>>,
    window: Option<Window>,
    // device setup
    instance: Option<Instance>,
    surface: Option<Surface>,
    adapter: Option<Adapter>,
    device: Option<Device>,
    queue: Option<Queue>,
    texture_format: Option<TextureFormat>,
    // pipeline
    uniform_buffer: Option<Buffer>,
    bind_group: Option<BindGroup>,
    render_pipeline: Option<RenderPipeline>,
    // mesh
    triangle_mesh: Option<TriangleMesh>,
}

impl Renderer {
    pub async fn new<'a>(event_loop: EventLoop<()>, window: Window) -> Renderer {
        Renderer {
            event_loop: Some(event_loop),
            window: Some(window),
            instance: None,
            surface: None,
            adapter: None,
            device: None,
            queue: None,
            texture_format: None,
            uniform_buffer: None,
            bind_group: None,
            render_pipeline: None,
            triangle_mesh: None,
        }
    }

    pub async fn start(&mut self) {
        self.setup_device().await;
        self.create_assets();
        self.make_pipeline(Cow::Borrowed(include_str!("triangle.wgsl")));
        self.render();
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
    async fn setup_device(&mut self) {
        let window = self.window.as_ref().unwrap();
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
        let texture_format = swapchain_capabilities.formats[0];

        self.instance = Some(instance);
        self.adapter = Some(adapter);
        self.surface = Some(surface);
        self.device = Some(device);
        self.queue = Some(queue);
        self.texture_format = Some(texture_format);
    }

    fn create_assets(&mut self) {
        let device = self.device.as_ref().unwrap();
        self.triangle_mesh = Some(TriangleMesh::new(device));
    }

    fn make_pipeline(&mut self, shader_path: Cow<str>) {
        let device = self.device.as_ref().unwrap();
        let texture_format = self.texture_format.as_ref().unwrap();
        let vertex_buffer_layout = self
            .triangle_mesh
            .as_mut()
            .unwrap()
            .vertex_buffer_layout
            .take()
            .unwrap();

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
                buffers: &[vertex_buffer_layout],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                targets: &[Some(texture_format.to_owned().into())],
            }),
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                ..wgpu::PrimitiveState::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
        });

        self.uniform_buffer = Some(uniform_buffer);
        self.bind_group = Some(bind_group);
        self.render_pipeline = Some(render_pipeline);
    }

    fn render(&mut self) {
        let window = self.window.take().unwrap();
        let device = self.device.take().unwrap();
        let queue = self.queue.take().unwrap();
        let texture_format = self.texture_format.take().unwrap();
        let surface = self.surface.take().unwrap();
        let adapter = self.adapter.take().unwrap();
        let render_pipeline = self.render_pipeline.take().unwrap();
        let vertex_buffer = self
            .triangle_mesh
            .as_mut()
            .unwrap()
            .vertex_buffer
            .take()
            .unwrap();
        let uniform_buffer = self.uniform_buffer.take().unwrap();
        let bind_group = self.bind_group.take().unwrap();

        let size = window.inner_size();

        let swapchain_capabilities = surface.get_capabilities(&adapter);

        let mut config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format: texture_format.to_owned(),
            width: size.width,
            height: size.height,
            present_mode: wgpu::PresentMode::Fifo,
            alpha_mode: swapchain_capabilities.alpha_modes[0],
            view_formats: vec![],
        };

        surface.configure(&device, &config);

        let projection =
            glam::Mat4::perspective_rh_gl(std::f32::consts::PI / 4., 800. / 600., 0.1, 10.);

        let view = glam::Mat4::look_at_rh(
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

        queue.write_buffer(&uniform_buffer, 64, bytemuck::cast_slice(view.as_ref()));
        queue.write_buffer(
            &uniform_buffer,
            128,
            bytemuck::cast_slice(projection.as_ref()),
        );

        let mut t = 0.;
        self.event_loop
            .take()
            .unwrap()
            .run(move |event, _, control_flow| {
                let mut command_encoder =
                    device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
                match event {
                    Event::WindowEvent {
                        event: WindowEvent::Resized(size),
                        ..
                    } => {
                        // Reconfigure the surface with the new size
                        config.width = size.width;
                        config.height = size.height;
                        surface.configure(&device, &config);
                        // On macos the window needs to be redrawn manually after resizing
                        window.request_redraw();
                    }
                    Event::RedrawRequested(_) | Event::MainEventsCleared => {
                        t += 0.05;
                        if t > 2.0 * std::f32::consts::PI {
                            t -= 2.0 * std::f32::consts::PI;
                        }

                        let rotate = glam::Mat4::from_rotation_z(t);
                        queue.write_buffer(
                            &uniform_buffer,
                            0,
                            bytemuck::cast_slice(rotate.as_ref()),
                        );

                        let texture = surface
                            .get_current_texture()
                            .expect("Failed to load texture.");
                        let texture_view = texture
                            .texture
                            .create_view(&wgpu::TextureViewDescriptor::default());

                        let mut render_pass =
                            command_encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                                label: None,
                                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                                    view: &texture_view,
                                    resolve_target: None,
                                    ops: wgpu::Operations::<wgpu::Color> {
                                        load: wgpu::LoadOp::Clear(wgpu::Color {
                                            r: 0.5,
                                            g: 0.,
                                            b: 0.25,
                                            a: 1.,
                                        }),
                                        store: true,
                                    },
                                })],
                                depth_stencil_attachment: None,
                            });
                        render_pass.set_pipeline(&render_pipeline);
                        render_pass.set_vertex_buffer(0, vertex_buffer.slice(..));
                        render_pass.set_bind_group(0, &bind_group, &[]);
                        render_pass.draw(0..3, 0..1);
                        std::mem::drop(render_pass);
                        queue.submit(Some(command_encoder.finish()));
                        texture.present(); // one extra step compared to javascript
                    }
                    Event::WindowEvent {
                        event: WindowEvent::CloseRequested,
                        ..
                    } => *control_flow = ControlFlow::Exit,
                    _ => {}
                }
            });
    }
}
