//! User-space SDK для USB class-драйверов поверх `/dev/bus/usb/BBB/DDD` (`usbfs`).

use wunix_drv::abi::usbfs::{
    UsbDeviceInfo, UsbfsBulkTransfer, UsbfsCtrlTransfer, UsbfsIntTransfer, UsbfsRawDescriptor,
    USBDEVFS_BULK, USBDEVFS_CLAIMINTERFACE, USBDEVFS_CONTROL, USBDEVFS_GET_DEVICE_INFO,
    USBDEVFS_GET_RAW_DESCRIPTOR, USBDEVFS_INTERRUPT, USBDEVFS_RELEASEINTERFACE, USBDEVFS_RESET,
};
use wunix_drv::DriverError;

use crate::{close, ioctl, open, O_RDWR};

/// Абстрактный транспорт USB-устройства (позволяет запускать class-драйверы и в Ring 3, и в mock-тестах).
pub trait UsbfsTransport {
    fn device_info(&self) -> Result<UsbDeviceInfo, DriverError>;
    fn raw_config_descriptor(&self, buf: &mut [u8]) -> Result<usize, DriverError>;
    fn control_transfer(
        &mut self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, DriverError>;
    fn bulk_transfer(&mut self, ep: u8, data: &mut [u8], timeout_ms: u32) -> Result<usize, DriverError>;
    fn interrupt_transfer(&mut self, ep: u8, data: &mut [u8], timeout_ms: u32) -> Result<usize, DriverError>;
    fn claim_interface(&mut self, iface: u32) -> Result<(), DriverError>;
    fn release_interface(&mut self, iface: u32) -> Result<(), DriverError>;
    fn reset(&mut self) -> Result<(), DriverError>;
}

pub struct UsbfsDevice {
    fd: u64,
}

impl UsbfsDevice {
    pub fn open(path_cstr: &[u8]) -> Result<Self, DriverError> {
        let res = open(path_cstr, O_RDWR as u64, 0);
        if res < 0 {
            Err(DriverError::from_errno(res as i32))
        } else {
            Ok(Self { fd: res as u64 })
        }
    }
}

impl Drop for UsbfsDevice {
    fn drop(&mut self) {
        close(self.fd);
    }
}

impl UsbfsTransport for UsbfsDevice {
    fn device_info(&self) -> Result<UsbDeviceInfo, DriverError> {
        let mut info = UsbDeviceInfo::default();
        let rc = ioctl(self.fd, USBDEVFS_GET_DEVICE_INFO as u64, &mut info as *mut _ as u64);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(info)
        }
    }

    fn raw_config_descriptor(&self, buf: &mut [u8]) -> Result<usize, DriverError> {
        let mut req = UsbfsRawDescriptor {
            buf: buf.as_mut_ptr() as u64,
            len: buf.len() as u32,
            actual_len: 0,
        };
        let rc = ioctl(self.fd, USBDEVFS_GET_RAW_DESCRIPTOR as u64, &mut req as *mut _ as u64);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok((req.actual_len as usize).min(buf.len()))
        }
    }

    fn control_transfer(
        &mut self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, DriverError> {
        let mut req = UsbfsCtrlTransfer {
            bm_request_type,
            b_request,
            w_value,
            w_index,
            w_length: data.len() as u16,
            timeout_ms,
            padding: 0,
            data: if data.is_empty() { 0 } else { data.as_mut_ptr() as u64 },
        };
        let rc = ioctl(self.fd, USBDEVFS_CONTROL as u64, &mut req as *mut _ as u64);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(rc as usize)
        }
    }

    fn bulk_transfer(&mut self, ep: u8, data: &mut [u8], timeout_ms: u32) -> Result<usize, DriverError> {
        let mut req = UsbfsBulkTransfer {
            ep: ep as u32,
            len: data.len() as u32,
            timeout_ms,
            padding: 0,
            data: if data.is_empty() { 0 } else { data.as_mut_ptr() as u64 },
        };
        let rc = ioctl(self.fd, USBDEVFS_BULK as u64, &mut req as *mut _ as u64);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(rc as usize)
        }
    }

    fn interrupt_transfer(&mut self, ep: u8, data: &mut [u8], timeout_ms: u32) -> Result<usize, DriverError> {
        let mut req = UsbfsIntTransfer {
            ep: ep as u32,
            len: data.len() as u32,
            timeout_ms,
            padding: 0,
            data: if data.is_empty() { 0 } else { data.as_mut_ptr() as u64 },
        };
        let rc = ioctl(self.fd, USBDEVFS_INTERRUPT as u64, &mut req as *mut _ as u64);
        if rc < 0 {
            Err(DriverError::from_errno(rc as i32))
        } else {
            Ok(rc as usize)
        }
    }

    fn claim_interface(&mut self, iface: u32) -> Result<(), DriverError> {
        let mut n = iface;
        let rc = ioctl(self.fd, USBDEVFS_CLAIMINTERFACE as u64, &mut n as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }

    fn release_interface(&mut self, iface: u32) -> Result<(), DriverError> {
        let mut n = iface;
        let rc = ioctl(self.fd, USBDEVFS_RELEASEINTERFACE as u64, &mut n as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }

    fn reset(&mut self) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, USBDEVFS_RESET as u64, 0);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }
}

/// Эталонный user-space драйвер USB Mass Storage (SCSI Bulk-Only Transport поверх `usbfs`).
pub struct UsbMassStorageUserDriver<T: UsbfsTransport> {
    transport: T,
    ep_in: u8,
    ep_out: u8,
    tag: u32,
}

impl<T: UsbfsTransport> UsbMassStorageUserDriver<T> {
    pub fn new(transport: T, ep_in: u8, ep_out: u8) -> Self {
        Self {
            transport,
            ep_in,
            ep_out,
            tag: 1,
        }
    }

    fn scsi_cmd(&mut self, cdb: &[u8], data: &mut [u8], is_in: bool) -> Result<(), DriverError> {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);

        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        cbw[12] = if is_in { 0x80 } else { 0x00 };
        let cdb_len = cdb.len().min(16);
        cbw[14] = cdb_len as u8;
        cbw[15..15 + cdb_len].copy_from_slice(&cdb[..cdb_len]);

        self.transport.bulk_transfer(self.ep_out, &mut cbw, 1000)?;
        if !data.is_empty() {
            let ep = if is_in { self.ep_in } else { self.ep_out };
            self.transport.bulk_transfer(ep, data, 2000)?;
        }

        let mut csw = [0u8; 13];
        let got = self.transport.bulk_transfer(self.ep_in, &mut csw, 1000)?;
        if got < 13 || u32::from_le_bytes([csw[0], csw[1], csw[2], csw[3]]) != 0x5342_5355 {
            return Err(DriverError::ProtocolError);
        }
        if csw[12] != 0 {
            return Err(DriverError::IoError);
        }
        Ok(())
    }

    pub fn read_capacity(&mut self) -> Result<(u64, u32), DriverError> {
        let mut cap = [0u8; 8];
        let mut cdb = [0u8; 10];
        cdb[0] = 0x25;
        self.scsi_cmd(&cdb, &mut cap, true)?;
        let last_lba = u32::from_be_bytes([cap[0], cap[1], cap[2], cap[3]]) as u64;
        let blk_size = u32::from_be_bytes([cap[4], cap[5], cap[6], cap[7]]);
        Ok((last_lba + 1, blk_size))
    }

    pub fn read_blocks(&mut self, lba: u32, count: u16, out: &mut [u8]) -> Result<(), DriverError> {
        let mut cdb = [0u8; 10];
        cdb[0] = 0x28;
        cdb[2..6].copy_from_slice(&lba.to_be_bytes());
        cdb[7..9].copy_from_slice(&count.to_be_bytes());
        self.scsi_cmd(&cdb, out, true)
    }

    pub fn write_blocks(&mut self, lba: u32, count: u16, data: &[u8]) -> Result<(), DriverError> {
        let mut cdb = [0u8; 10];
        cdb[0] = 0x2A;
        cdb[2..6].copy_from_slice(&lba.to_be_bytes());
        cdb[7..9].copy_from_slice(&count.to_be_bytes());
        let mut copy_buf = [0u8; 4096];
        if data.len() > copy_buf.len() {
            return Err(DriverError::NoMemory);
        }
        copy_buf[..data.len()].copy_from_slice(data);
        self.scsi_cmd(&cdb, &mut copy_buf[..data.len()], false)
    }
}

/// Эталонный user-space драйвер USB HID поверх `usbfs` interrupt transfers.
pub struct UsbHidUserDriver<T: UsbfsTransport> {
    transport: T,
    ep_intr_in: u8,
}

impl<T: UsbfsTransport> UsbHidUserDriver<T> {
    pub fn new(transport: T, ep_intr_in: u8) -> Self {
        Self {
            transport,
            ep_intr_in,
        }
    }

    /// Переводит HID устройство в Boot Protocol (`SET_PROTOCOL = 0`).
    pub fn set_boot_protocol(&mut self, iface: u16) -> Result<(), DriverError> {
        self.transport
            .control_transfer(0x21, 0x0B, 0, iface, &mut [], 500)?;
        Ok(())
    }

    pub fn poll_mouse_report(&mut self, timeout_ms: u32) -> Result<(u8, i8, i8), DriverError> {
        let mut buf = [0u8; 4];
        let n = self.transport.interrupt_transfer(self.ep_intr_in, &mut buf, timeout_ms)?;
        if n < 3 {
            return Err(DriverError::ProtocolError);
        }
        Ok((buf[0], buf[1] as i8, buf[2] as i8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUsbDiskAndMouse {
        sectors: [[u8; 512]; 4],
        pending_cdb: [u8; 16],
        pending_len: usize,
        last_written_lba: usize,
        mouse_report: [u8; 3],
        boot_proto_set: bool,
    }

    impl UsbfsTransport for MockUsbDiskAndMouse {
        fn device_info(&self) -> Result<UsbDeviceInfo, DriverError> {
            Ok(UsbDeviceInfo {
                bus: 1,
                devnum: 2,
                vendor_id: 0x0627,
                product_id: 0x0001,
                ep_bulk_in: 0x81,
                ep_bulk_out: 0x02,
                ep_intr_in: 0x83,
                ..Default::default()
            })
        }
        fn raw_config_descriptor(&self, _buf: &mut [u8]) -> Result<usize, DriverError> {
            Ok(0)
        }
        fn control_transfer(
            &mut self,
            bm: u8,
            req: u8,
            _v: u16,
            _i: u16,
            _d: &mut [u8],
            _t: u32,
        ) -> Result<usize, DriverError> {
            if bm == 0x21 && req == 0x0B {
                self.boot_proto_set = true;
            }
            Ok(0)
        }
        fn bulk_transfer(&mut self, ep: u8, data: &mut [u8], _t: u32) -> Result<usize, DriverError> {
            if ep == 0x02 && data.len() == 31 && &data[0..4] == &0x4342_5355u32.to_le_bytes() {
                self.pending_cdb.copy_from_slice(&data[15..31]);
                self.pending_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
                self.last_written_lba = u32::from_be_bytes([data[17], data[18], data[19], data[20]]) as usize;
                return Ok(31);
            }
            if ep == 0x02 && self.pending_cdb[0] == 0x2A {
                self.sectors[self.last_written_lba].copy_from_slice(&data[..512]);
                return Ok(512);
            }
            if ep == 0x81 && data.len() == 13 {
                data[0..4].copy_from_slice(&0x5342_5355u32.to_le_bytes());
                data[4..8].copy_from_slice(&1u32.to_le_bytes());
                data[12] = 0;
                return Ok(13);
            }
            if ep == 0x81 && self.pending_cdb[0] == 0x25 {
                data[0..4].copy_from_slice(&3u32.to_be_bytes());
                data[4..8].copy_from_slice(&512u32.to_be_bytes());
                return Ok(8);
            }
            if ep == 0x81 && self.pending_cdb[0] == 0x28 {
                data[..512].copy_from_slice(&self.sectors[self.last_written_lba]);
                return Ok(512);
            }
            Err(DriverError::IoError)
        }
        fn interrupt_transfer(&mut self, ep: u8, data: &mut [u8], _t: u32) -> Result<usize, DriverError> {
            if ep == 0x83 {
                data[..3].copy_from_slice(&self.mouse_report);
                return Ok(3);
            }
            Err(DriverError::InvalidArgument)
        }
        fn claim_interface(&mut self, _iface: u32) -> Result<(), DriverError> { Ok(()) }
        fn release_interface(&mut self, _iface: u32) -> Result<(), DriverError> { Ok(()) }
        fn reset(&mut self) -> Result<(), DriverError> { Ok(()) }
    }

    #[test]
    fn test_usbfs_mass_storage_and_hid_emulated() {
        let mock = MockUsbDiskAndMouse {
            sectors: [[0u8; 512]; 4],
            pending_cdb: [0u8; 16],
            pending_len: 0,
            last_written_lba: 0,
            mouse_report: [0x01, 12, (-5i8) as u8],
            boot_proto_set: false,
        };
        let mut disk = UsbMassStorageUserDriver::new(mock, 0x81, 0x02);
        assert_eq!(disk.read_capacity(), Ok((4, 512)));

        let mut tx = [0u8; 512];
        tx[0..5].copy_from_slice(b"USB3!");
        assert_eq!(disk.write_blocks(2, 1, &tx), Ok(()));

        let mut rx = [0u8; 512];
        assert_eq!(disk.read_blocks(2, 1, &mut rx), Ok(()));
        assert_eq!(&rx[0..5], b"USB3!");

        let mut hid = UsbHidUserDriver::new(disk.transport, 0x83);
        assert_eq!(hid.set_boot_protocol(0), Ok(()));
        assert!(hid.transport.boot_proto_set);
        assert_eq!(hid.poll_mouse_report(10), Ok((0x01, 12, -5)));
    }
}
