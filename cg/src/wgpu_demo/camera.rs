use glam::{vec3, Mat4, Vec3};

pub struct Camera {
    position: Vec3,
    eulers: Vec3,
    view: Mat4,
    forwards: Vec3,
    right: Vec3,
    up: Vec3,
}

impl Camera {
    pub fn new(position: Vec3, theta: f32, phi: f32) -> Self {
        Camera {
            position,
            eulers: Vec3::new(0., phi, theta),
            view: Mat4::ZERO,
            forwards: Vec3::ZERO,
            right: Vec3::ZERO,
            up: Vec3::ZERO,
        }
    }

    pub fn update(&mut self) {
        self.forwards = vec3(
            self.eulers[2].to_radians().cos() * self.eulers[1].to_radians().cos(),
            self.eulers[2].to_radians().sin() * self.eulers[1].to_radians().cos(),
            self.eulers[1].to_radians().sin(),
        );
        self.right = self.forwards.cross(vec3(0., 0., 1.));
        self.up = self.right.cross(self.forwards);

        let target = self.position + self.forwards;
        self.view = Mat4::look_at_rh(self.position, target, self.up);
    }

    pub fn get_view(&self) -> Mat4 {
        self.view
    }
}
