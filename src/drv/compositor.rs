//! User-space SDK композитора: `/dev/fb0` (mmap + FBIO_FLUSH), `/dev/shm` и `/dev/input/eventN`.

use core::mem::size_of;
use core::ptr::read_unaligned;

use wunix_drv::abi::display::{FbRect, InputEventRecord, FBIO_FLUSH};
use wunix_drv::DriverError;

use crate::{
    close, ftruncate, ioctl, mmap, munmap, open, read, MAP_FAILED, MAP_SHARED, O_CREAT,
    O_NONBLOCK, O_RDONLY, O_RDWR, PROT_READ, PROT_WRITE,
};

pub const FBIOGET_VSCREENINFO: u64 = 0x4600;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FbVarScreenInfo {
    pub xres: u32,
    pub yres: u32,
    pub xres_virtual: u32,
    pub yres_virtual: u32,
    pub xoffset: u32,
    pub yoffset: u32,
    pub bits_per_pixel: u32,
    pub _pad: [u32; 33],
}

impl Default for FbVarScreenInfo {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

pub struct FramebufferClient {
    fd: u64,
    ptr: *mut u32,
    byte_len: usize,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
}

impl FramebufferClient {
    pub fn open_fb0() -> Result<Self, DriverError> {
        let fd_res = open(b"/dev/fb0\0", O_RDWR as u64, 0);
        if fd_res < 0 {
            return Err(DriverError::from_errno(fd_res as i32));
        }
        let fd = fd_res as u64;

        let mut vinfo = FbVarScreenInfo::default();
        let rc = ioctl(fd, FBIOGET_VSCREENINFO, &mut vinfo as *mut _ as u64);
        if rc < 0 || vinfo.xres == 0 || vinfo.yres == 0 {
            close(fd);
            return Err(DriverError::IoError);
        }

        let byte_len = (vinfo.xres as usize) * (vinfo.yres as usize) * ((vinfo.bits_per_pixel.max(32) / 8) as usize);
        let mapped = unsafe { mmap(0, byte_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i64, 0) };
        if mapped < 0 || (mapped as usize) == MAP_FAILED {
            close(fd);
            return Err(DriverError::NoMemory);
        }

        Ok(Self {
            fd,
            ptr: mapped as *mut u32,
            byte_len,
            width: vinfo.xres,
            height: vinfo.yres,
            bpp: vinfo.bits_per_pixel,
        })
    }

    pub fn pixels_mut(&mut self) -> &mut [u32] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, (self.width * self.height) as usize) }
    }

    pub fn flush_rect(&self, rect: FbRect) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, FBIO_FLUSH as u64, &rect as *const _ as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }
}

impl Drop for FramebufferClient {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as usize, self.byte_len);
        }
        close(self.fd);
    }
}

pub struct ShmSurface {
    fd: u64,
    ptr: *mut u8,
    size: usize,
}

impl ShmSurface {
    pub fn open_or_create(path_cstr: &[u8], size: usize) -> Result<Self, DriverError> {
        let res = open(path_cstr, (O_RDWR | O_CREAT) as u64, 0o666);
        if res < 0 {
            return Err(DriverError::from_errno(res as i32));
        }
        let fd = res as u64;
        let _ = ftruncate(fd, size as u64);
        let mapped = unsafe { mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i64, 0) };
        if mapped < 0 || (mapped as usize) == MAP_FAILED {
            close(fd);
            return Err(DriverError::NoMemory);
        }
        Ok(Self {
            fd,
            ptr: mapped as *mut u8,
            size,
        })
    }

    pub fn as_u32_mut(&mut self) -> &mut [u32] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u32, self.size / 4) }
    }
}

impl Drop for ShmSurface {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as usize, self.size);
        }
        close(self.fd);
    }
}

pub struct InputEventReader {
    fd: u64,
}

impl InputEventReader {
    pub fn open(path_cstr: &[u8]) -> Result<Self, DriverError> {
        let res = open(path_cstr, (O_RDONLY | O_NONBLOCK) as u64, 0);
        if res < 0 {
            Err(DriverError::from_errno(res as i32))
        } else {
            Ok(Self { fd: res as u64 })
        }
    }

    pub fn poll_event(&self) -> Result<Option<InputEventRecord>, DriverError> {
        let mut buf = [0u8; size_of::<InputEventRecord>()];
        let n = read(self.fd, &mut buf) as isize;
        if n == 0 || n == -11 {
            return Ok(None);
        }
        if n < 0 {
            return Err(DriverError::from_errno(n as i32));
        }
        if (n as usize) < size_of::<InputEventRecord>() {
            return Ok(None);
        }
        Ok(Some(unsafe { read_unaligned(buf.as_ptr() as *const InputEventRecord) }))
    }
}

impl Drop for InputEventReader {
    fn drop(&mut self) {
        close(self.fd);
    }
}

#[derive(Clone, Copy)]
pub struct CompositorSurface<'a> {
    pub id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub z_order: u16,
    pub visible: bool,
    pub pixels: &'a [u32],
}

/// Программный композитор с Z-сортировкой окон и композицией только повреждённых областей (damage rects).
pub fn compose_damage_rect(
    dst: &mut [u32],
    fb_width: u32,
    fb_height: u32,
    bg_color: u32,
    damage: FbRect,
    surfaces: &[CompositorSurface<'_>],
) {
    let x0 = damage.x.min(fb_width);
    let y0 = damage.y.min(fb_height);
    let x1 = damage.x.saturating_add(damage.width).min(fb_width);
    let y1 = damage.y.saturating_add(damage.height).min(fb_height);

    for py in y0..y1 {
        let row = (py * fb_width) as usize;
        for px in x0..x1 {
            dst[row + px as usize] = bg_color;
        }
    }

    // Отрисовываем поверхности по возрастанию z_order (простым выбором без аллокаций).
    let mut drawn_mask = 0u64;
    let count = surfaces.len().min(64);
    for _ in 0..count {
        let mut best_idx = None;
        let mut best_z = u16::MAX;
        for (i, s) in surfaces.iter().take(count).enumerate() {
            if (drawn_mask & (1u64 << i)) == 0 && s.visible && s.z_order <= best_z {
                best_z = s.z_order;
                best_idx = Some(i);
            }
        }
        let Some(idx) = best_idx else { break };
        drawn_mask |= 1u64 << idx;
        let s = &surfaces[idx];

        let sx0 = x0.max(s.x.max(0) as u32);
        let sy0 = y0.max(s.y.max(0) as u32);
        let sx1 = x1.min((s.x + s.width as i32).max(0) as u32);
        let sy1 = y1.min((s.y + s.height as i32).max(0) as u32);
        for py in sy0..sy1 {
            let src_y = (py as i32 - s.y) as u32;
            for px in sx0..sx1 {
                let src_x = (px as i32 - s.x) as u32;
                let s_idx = (src_y * s.width + src_x) as usize;
                if let Some(&pixel) = s.pixels.get(s_idx) {
                    dst[(py * fb_width + px) as usize] = pixel;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compositor_z_order_and_damage_clipping() {
        let mut fb = [0u32; 8 * 8];
        let back = [0x0011_2233u32; 16]; // 4x4 window at (1, 1)
        let front = [0x00FF_0000u32; 4]; // 2x2 window at (2, 2)

        let surfaces = [
            CompositorSurface {
                id: 1,
                x: 2,
                y: 2,
                width: 2,
                height: 2,
                z_order: 10,
                visible: true,
                pixels: &front,
            },
            CompositorSurface {
                id: 2,
                x: 1,
                y: 1,
                width: 4,
                height: 4,
                z_order: 1,
                visible: true,
                pixels: &back,
            },
        ];

        compose_damage_rect(
            &mut fb,
            8,
            8,
            0x0000_0000,
            FbRect {
                x: 0,
                y: 0,
                width: 8,
                height: 8,
            },
            &surfaces,
        );

        assert_eq!(fb[0], 0x0000_0000); // background
        assert_eq!(fb[1 * 8 + 1], 0x0011_2233); // lower z window
        assert_eq!(fb[2 * 8 + 2], 0x00FF_0000); // upper z window occludes lower
        assert_eq!(fb[4 * 8 + 4], 0x0011_2233); // exposed part of lower window
    }
}
