use glam::{Mat4, Vec3};

pub struct Triangle {
    position: Vec3,
    eulers: Vec3,
    model: Mat4,
}

impl Triangle {
    pub fn new(position: Vec3, theta: f32) -> Triangle {
        let mut e = Vec3::ZERO;
        e[2] = theta;
        Triangle {
            position: position,
            eulers: e,
            model: Mat4::ZERO,
        }
    }

    pub fn update(&mut self) {
        self.eulers[2] += 1.;
        self.eulers[2] %= 360.;

        self.model = Mat4::from_rotation_z(self.eulers[2].to_radians())
            * Mat4::from_translation(self.position);
    }

    pub fn get_model(&self) -> Mat4 {
        return self.model;
    }
}
