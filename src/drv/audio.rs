//! User-space SDK для аудио-сервера (`audiod`) поверх `/dev/snd/pcm0` и `/dev/dsp`.

use wunix_drv::abi::audio::{
    AudioDeviceInfo, AudioIpcHeader, AudioIpcOp, AUDIO_IPC_MAGIC, SNDCTL_DSP_CHANNELS,
    SNDCTL_DSP_GETINFO, SNDCTL_DSP_SETFMT, SNDCTL_DSP_SETVOLUME, SNDCTL_DSP_SPEED,
    SNDCTL_DSP_SYNC,
};
use wunix_drv::DriverError;

use crate::{close, ioctl, open, write, O_WRONLY};

pub trait AudioPcmSink {
    fn set_rate(&mut self, hz: u32) -> Result<u32, DriverError>;
    fn set_channels(&mut self, channels: u32) -> Result<u32, DriverError>;
    fn set_format(&mut self, fmt: u32) -> Result<u32, DriverError>;
    fn set_volume(&mut self, percent: u32) -> Result<(), DriverError>;
    fn write_pcm(&mut self, samples: &[u8]) -> Result<usize, DriverError>;
    fn sync(&mut self) -> Result<(), DriverError>;
    fn info(&self) -> Result<AudioDeviceInfo, DriverError>;
}

pub struct AudioDeviceClient {
    fd: u64,
}

impl AudioDeviceClient {
    pub fn open_default() -> Result<Self, DriverError> {
        let res = open(b"/dev/snd/pcm0\0", O_WRONLY as u64, 0);
        if res >= 0 {
            return Ok(Self { fd: res as u64 });
        }
        let dsp = open(b"/dev/dsp\0", O_WRONLY as u64, 0);
        if dsp < 0 {
            Err(DriverError::from_errno(dsp as i32))
        } else {
            Ok(Self { fd: dsp as u64 })
        }
    }
}

impl Drop for AudioDeviceClient {
    fn drop(&mut self) {
        close(self.fd);
    }
}

impl AudioPcmSink for AudioDeviceClient {
    fn set_rate(&mut self, mut hz: u32) -> Result<u32, DriverError> {
        let rc = ioctl(self.fd, SNDCTL_DSP_SPEED as u64, &mut hz as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(hz) }
    }

    fn set_channels(&mut self, mut channels: u32) -> Result<u32, DriverError> {
        let rc = ioctl(self.fd, SNDCTL_DSP_CHANNELS as u64, &mut channels as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(channels) }
    }

    fn set_format(&mut self, mut fmt: u32) -> Result<u32, DriverError> {
        let rc = ioctl(self.fd, SNDCTL_DSP_SETFMT as u64, &mut fmt as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(fmt) }
    }

    fn set_volume(&mut self, mut percent: u32) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, SNDCTL_DSP_SETVOLUME as u64, &mut percent as *mut u32 as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }

    fn write_pcm(&mut self, samples: &[u8]) -> Result<usize, DriverError> {
        let n = write(self.fd, samples) as isize;
        if n < 0 { Err(DriverError::from_errno(n as i32)) } else { Ok(n as usize) }
    }

    fn sync(&mut self) -> Result<(), DriverError> {
        let rc = ioctl(self.fd, SNDCTL_DSP_SYNC as u64, 0);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(()) }
    }

    fn info(&self) -> Result<AudioDeviceInfo, DriverError> {
        let mut info = AudioDeviceInfo::default();
        let rc = ioctl(self.fd, SNDCTL_DSP_GETINFO as u64, &mut info as *mut _ as u64);
        if rc < 0 { Err(DriverError::from_errno(rc as i32)) } else { Ok(info) }
    }
}

#[derive(Clone, Copy)]
pub struct AudioStreamSlot {
    pub active: bool,
    pub muted: bool,
    pub volume: u8,
    pub sample_rate: u32,
}

impl Default for AudioStreamSlot {
    fn default() -> Self {
        Self {
            active: false,
            muted: false,
            volume: 100,
            sample_rate: 48_000,
        }
    }
}

/// Программный PCM S16LE микшер без аллокаций для user-space аудио-сервера `audiod`.
pub struct AudioMixer<const STREAMS: usize> {
    pub streams: [AudioStreamSlot; STREAMS],
    pub master_volume: u8,
}

impl<const STREAMS: usize> AudioMixer<STREAMS> {
    pub const fn new() -> Self {
        Self {
            streams: [AudioStreamSlot {
                active: false,
                muted: false,
                volume: 100,
                sample_rate: 48_000,
            }; STREAMS],
            master_volume: 100,
        }
    }

    pub fn open_stream(&mut self, sample_rate: u32, volume: u8) -> Option<usize> {
        for (idx, s) in self.streams.iter_mut().enumerate() {
            if !s.active {
                s.active = true;
                s.muted = false;
                s.volume = volume.min(100);
                s.sample_rate = sample_rate;
                return Some(idx);
            }
        }
        None
    }

    pub fn close_stream(&mut self, stream_id: usize) {
        if let Some(s) = self.streams.get_mut(stream_id) {
            s.active = false;
        }
    }

    /// Смешивает несколько S16LE потоков с учётом громкости каждого потока, master volume и клиппинга.
    pub fn mix_s16le(&self, inputs: &[&[u8]], out: &mut [u8]) -> usize {
        let frames = out.len() / 2;
        for sample_idx in 0..frames {
            let mut acc: i32 = 0;
            let byte_off = sample_idx * 2;
            for (stream_idx, buf) in inputs.iter().enumerate() {
                if stream_idx >= STREAMS {
                    break;
                }
                let st = self.streams[stream_idx];
                if !st.active || st.muted || byte_off + 1 >= buf.len() {
                    continue;
                }
                let raw = i16::from_le_bytes([buf[byte_off], buf[byte_off + 1]]) as i32;
                let vol = (st.volume as i32 * self.master_volume as i32) / 10_000;
                // Сохраняем точность через (st * master) в долях 10000
                let scaled = (raw * st.volume as i32 * self.master_volume as i32) / 10_000;
                let _ = vol;
                acc = acc.saturating_add(scaled);
            }
            let clamped = acc.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            out[byte_off..byte_off + 2].copy_from_slice(&clamped.to_le_bytes());
        }
        frames * 2
    }
}

pub fn make_ipc_ack(op: AudioIpcOp, stream_id: u32, status: i32) -> AudioIpcHeader {
    AudioIpcHeader {
        magic: AUDIO_IPC_MAGIC,
        op: op as u32,
        stream_id,
        status,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_mixer_s16le_saturation_and_volume() {
        let mut mixer = AudioMixer::<4>::new();
        let s0 = mixer.open_stream(48000, 100).unwrap();
        let s1 = mixer.open_stream(48000, 50).unwrap();
        assert_eq!((s0, s1), (0, 1));

        let mut a = [0u8; 4];
        a[0..2].copy_from_slice(&20_000i16.to_le_bytes());
        a[2..4].copy_from_slice(&(-20_000i16).to_le_bytes());

        let mut b = [0u8; 4];
        b[0..2].copy_from_slice(&30_000i16.to_le_bytes()); // 50% -> +15_000 -> total 35_000 -> clamps to 32767
        b[2..4].copy_from_slice(&(-10_000i16).to_le_bytes()); // 50% -> -5_000 -> total -25_000

        let mut out = [0u8; 4];
        let n = mixer.mix_s16le(&[&a, &b], &mut out);
        assert_eq!(n, 4);
        assert_eq!(i16::from_le_bytes([out[0], out[1]]), i16::MAX);
        assert_eq!(i16::from_le_bytes([out[2], out[3]]), -25_000);

        let ack = make_ipc_ack(AudioIpcOp::Ack, s0 as u32, 0);
        assert_eq!(ack.magic, AUDIO_IPC_MAGIC);
    }
}
