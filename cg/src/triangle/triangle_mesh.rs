use wgpu::{Buffer, Device, VertexBufferLayout};
// TODO return data in struct

pub struct TriangleMesh {
    pub vertex_buffer: Option<Buffer>,
    pub vertex_buffer_layout: Option<VertexBufferLayout<'static>>,
}
impl TriangleMesh {
    pub fn new(device: &Device) -> TriangleMesh {
        let vertices: &[f32] = &[
            0.0, 0.0, 0.5, 1.0, 0.0, 0.0, //
            0.0, -0.5, -0.5, 0.0, 1.0, 0.0, //
            0.0, 0.5, -0.5, 0.0, 0.0, 1.0,
        ];

        let buffer_usage_flags = wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST;

        let vertex_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: std::mem::size_of_val(vertices) as wgpu::BufferAddress,
            usage: buffer_usage_flags,
            mapped_at_creation: true,
        });

        // Load vertices into the buffer

        let mut mapped_range = vertex_buffer.slice(..).get_mapped_range_mut();
        let target = bytemuck::cast_slice_mut::<u8, f32>(&mut mapped_range); // Assuming you're using `bytemuck` crate for this
        target.copy_from_slice(vertices);
        std::mem::drop(mapped_range);
        vertex_buffer.unmap();

        let vertex_buffer_layout = VertexBufferLayout {
            array_stride: 24,
            step_mode: wgpu::VertexStepMode::default(),
            attributes: &[
                wgpu::VertexAttribute {
                    shader_location: 0,
                    format: wgpu::VertexFormat::Float32x3,
                    offset: 0,
                },
                wgpu::VertexAttribute {
                    shader_location: 1,
                    format: wgpu::VertexFormat::Float32x3,
                    offset: 12,
                },
            ],
        };

        return TriangleMesh {
            vertex_buffer: Some(vertex_buffer),
            vertex_buffer_layout: Some(vertex_buffer_layout),
        };
    }
}
