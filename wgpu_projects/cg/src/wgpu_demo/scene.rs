use glam::vec3;

use super::{camera::Camera, triangle::Triangle};

pub struct Scene {
    triangles: Vec<Triangle>,
    player: Camera,
    object_data: Vec<f32>,
    triangles_count: u32,
}

impl Scene {
    pub fn new() -> Self {
        let mut triangles = Vec::<Triangle>::new();
        let mut object_data = Vec::<f32>::with_capacity(16 * 1024);
        let mut triangles_count = 0;
        for y in -5..4 {
            triangles.push(Triangle::new(vec3(2., y as f32, 0.), 0.));

            for j in 0..16 {
                object_data[16 * triangles_count + j] = 0.;
            }
            triangles_count += 1;
        }
        let player = Camera::new(vec3(-2., 0., 0.5), 0., 0.);
        return Scene {
            triangles,
            player,
            object_data,
            triangles_count: triangles_count as u32,
        };
    }
}
