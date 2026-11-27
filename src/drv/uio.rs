//! Клиентский интерфейс `/dev/uioN` для user-space драйверов оборудования поверх `BusIo`.

use core::ptr::{read_volatile, write_volatile};
use wunix_drv::abi::uio::{
    UioDeviceInfo, UIO_IOCTL_DISABLE_IRQ, UIO_IOCTL_ENABLE_IRQ, UIO_IOCTL_GET_INFO,
};
use wunix_drv::{BusIo, DriverError};

use crate::{close, ioctl, mmap, munmap, open, read, MAP_FAILED, MAP_SHARED, O_RDWR, PROT_READ, PROT_WRITE};

pub struct UioDevice {
    fd: u64,
    mmio: *mut u8,
    mmio_len: usize,
    info: UioDeviceInfo,
}

unsafe impl Send for UioDevice {}

impl UioDevice {
    /// Открывает `/dev/uioN` (строка пути должна заканчиваться нулевым байтом `\0`)
    /// и отображает MMIO-область устройства в виртуальную память процесса.
    pub fn open(path_cstr: &[u8]) -> Result<Self, DriverError> {
        let fd_res = open(path_cstr, O_RDWR as u64, 0);
        if fd_res < 0 {
            return Err(DriverError::from_errno(fd_res as i32));
        }
        let fd = fd_res as u64;

        let mut info = UioDeviceInfo::default();
        let rc = ioctl(fd, UIO_IOCTL_GET_INFO as u64, &mut info as *mut _ as u64);
        if rc < 0 {
            close(fd);
            return Err(DriverError::from_errno(rc as i32));
        }

        let len = (info.mem_size as usize).max(4096);
        let mapped = unsafe { mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i64, 0) };
        if mapped < 0 || (mapped as usize) == MAP_FAILED {
            close(fd);
            return Err(DriverError::NoMemory);
        }

        Ok(Self {
            fd,
            mmio: mapped as *mut u8,
            mmio_len: len,
            info,
        })
    }

    /// Конструктор поверх уже открытого/отображённого региона (удобно для эмуляции).
    pub unsafe fn from_raw_ptr(fd: u64, mmio: *mut u8, mmio_len: usize, info: UioDeviceInfo) -> Self {
        Self {
            fd,
            mmio,
            mmio_len,
            info,
        }
    }

    pub fn info(&self) -> &UioDeviceInfo {
        &self.info
    }

    pub fn enable_irq(&self) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, UIO_IOCTL_ENABLE_IRQ as u64, 0);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(())
        }
    }

    pub fn disable_irq(&self) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, UIO_IOCTL_DISABLE_IRQ as u64, 0);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(())
        }
    }

    /// Блокируется до следующего прерывания устройства и возвращает накопленный счётчик IRQ.
    pub fn wait_irq(&self) -> Result<u32, DriverError> {
        let mut cnt_bytes = [0u8; 4];
        let n = read(self.fd, &mut cnt_bytes) as isize;
        if n < 0 {
            return Err(DriverError::from_errno(n as i32));
        }
        if n < 4 {
            return Err(DriverError::IoError);
        }
        Ok(u32::from_le_bytes(cnt_bytes))
    }

    #[inline]
    fn check(&self, offset: usize, width: usize) {
        assert!(offset + width <= self.mmio_len, "uio: MMIO offset out of bounds");
    }
}

impl BusIo for UioDevice {
    fn read_u8(&self, offset: usize) -> u8 {
        self.check(offset, 1);
        unsafe { read_volatile(self.mmio.add(offset)) }
    }

    fn read_u16(&self, offset: usize) -> u16 {
        self.check(offset, 2);
        unsafe { read_volatile(self.mmio.add(offset) as *const u16) }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        self.check(offset, 4);
        unsafe { read_volatile(self.mmio.add(offset) as *const u32) }
    }

    fn write_u8(&mut self, offset: usize, val: u8) {
        self.check(offset, 1);
        unsafe { write_volatile(self.mmio.add(offset), val) }
    }

    fn write_u16(&mut self, offset: usize, val: u16) {
        self.check(offset, 2);
        unsafe { write_volatile(self.mmio.add(offset) as *mut u16, val) }
    }

    fn write_u32(&mut self, offset: usize, val: u32) {
        self.check(offset, 4);
        unsafe { write_volatile(self.mmio.add(offset) as *mut u32, val) }
    }
}

impl Drop for UioDevice {
    fn drop(&mut self) {
        if !self.mmio.is_null() && self.fd != u64::MAX {
            unsafe {
                munmap(self.mmio as usize, self.mmio_len);
            }
            close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wunix_drv::MockBusIo;

    /// Показывает, что один и тот же код драйвера работает и с `MockBusIo`, и с реальным `/dev/uioN`.
    fn probe_generic_device<B: BusIo>(bus: &mut B) -> Result<u32, DriverError> {
        bus.write_u32(0x00, 0x1); // Reset bit
        bus.wait_mask32(0x04, 0x01, 0x01, 16)?;
        Ok(bus.read_u32(0x08))
    }

    #[test]
    fn test_uio_driver_portable_over_mock_bus() {
        fn hw_emul(regs: &mut [u8; 64], offset: usize, val: u32) {
            if offset == 0x00 && val == 1 {
                regs[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
                regs[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
            }
        }
        let mut bus = MockBusIo::<64>::new().with_handler(hw_emul);
        assert_eq!(probe_generic_device(&mut bus), Ok(0xDEAD_BEEF));

        let mut backing = [0u8; 64];
        backing[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        backing[0x08..0x0C].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let mut raw_uio = unsafe {
            UioDevice::from_raw_ptr(u64::MAX, backing.as_mut_ptr(), 64, UioDeviceInfo::default())
        };
        assert_eq!(probe_generic_device(&mut raw_uio), Ok(0xCAFE_BABE));
    }
}
