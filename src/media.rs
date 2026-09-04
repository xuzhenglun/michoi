use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::thread::JoinHandle;

use anyhow::{Context, Result};

pub trait MediaEngine: Send {
    fn push_jpeg(&mut self, jpeg: &[u8], timestamp_micros: u64) -> Result<()>;
    fn static_snapshot(&self) -> &[u8];
    fn name(&self) -> &'static str;
    fn poll_h264(&mut self) -> Option<Vec<u8>> {
        None
    }
}

/// Black 320x240 JPEG. Lite mode intentionally never decodes the untrusted
/// door JPEG stream on the MT7628.
const BLACK_JPEG: &[u8] = include_bytes!("../assets/black.jpg");

pub struct LiteMediaEngine {
    snapshot: Vec<u8>,
    pub discarded_frames: u64,
}

impl LiteMediaEngine {
    pub fn new(snapshot: Option<Vec<u8>>) -> Self {
        Self {
            snapshot: snapshot.unwrap_or_else(|| BLACK_JPEG.to_vec()),
            discarded_frames: 0,
        }
    }
}

impl MediaEngine for LiteMediaEngine {
    fn push_jpeg(&mut self, _jpeg: &[u8], _timestamp_micros: u64) -> Result<()> {
        self.discarded_frames += 1;
        Ok(())
    }

    fn static_snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    fn name(&self) -> &'static str {
        "lite"
    }
}

/// Persistent FFmpeg process adapter. It is deliberately behind MediaEngine;
/// the OpenWrt lite build does not create it or require FFmpeg libraries.
pub struct FfmpegMediaEngine {
    child: Child,
    stdin: ChildStdin,
    snapshot: Vec<u8>,
    h264: Receiver<Vec<u8>>,
    _reader: JoinHandle<()>,
}

impl FfmpegMediaEngine {
    pub fn start(ffmpeg: PathBuf, width: u16, height: u16, fps: u16) -> Result<Self> {
        let mut child = Command::new(ffmpeg)
            .args([
                "-hide_banner",
                "-loglevel",
                "warning",
                "-f",
                "image2pipe",
                "-vcodec",
                "mjpeg",
                "-i",
                "pipe:0",
                "-an",
                "-vf",
                &format!("scale={width}:{height},fps={fps}"),
                "-c:v",
                "libx264",
                "-profile:v",
                "baseline",
                "-tune",
                "zerolatency",
                "-f",
                "h264",
                "pipe:1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("starting ffmpeg media adapter")?;
        let stdin = child.stdin.take().context("ffmpeg stdin unavailable")?;
        let mut stdout = child.stdout.take().context("ffmpeg stdout unavailable")?;
        let (sender, h264) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let Ok(size) = stdout.read(&mut buffer) else {
                    break;
                };
                if size == 0 {
                    break;
                }
                match sender.try_send(buffer[..size].to_vec()) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            snapshot: BLACK_JPEG.to_vec(),
            h264,
            _reader: reader,
        })
    }
}

impl MediaEngine for FfmpegMediaEngine {
    fn push_jpeg(&mut self, jpeg: &[u8], _timestamp_micros: u64) -> Result<()> {
        self.snapshot.clear();
        self.snapshot.extend_from_slice(jpeg);
        self.stdin.write_all(jpeg).context("writing JPEG to ffmpeg")
    }

    fn static_snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    fn name(&self) -> &'static str {
        "ffmpeg-process"
    }

    fn poll_h264(&mut self) -> Option<Vec<u8>> {
        self.h264.try_recv().ok()
    }
}

impl Drop for FfmpegMediaEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
