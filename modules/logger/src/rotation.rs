//! Write output to a file and rotate the files when limits have been exceeded.
//! When a rotation occurs, it attempts to open a file in the specific configuration path.
//! It just does its job (logging) if possible.
//! This simple file rotation is inspired by tracing crate.

use crate::error;
use core::pin::Pin;
use futures::task::{Context, Poll};
use std::future::Future;
use std::path::{Path, PathBuf};
use tokio::{
    fs::{self, File},
    io::{self, AsyncWrite},
};

/// define general result type for this module
#[allow(dead_code)]
type Result<T> = std::result::Result<T, error::LoggerError>;

/// RotationState is the state of the rotation
pub enum RotationState {
    PendingRename(Pin<Box<dyn Future<Output = io::Result<()>>>>),
    PendingCreate(Pin<Box<dyn Future<Output = io::Result<fs::File>>>>),
    PendingFlush,
    Done,
}

/// Define RotationMode enum which contains the different rotation mechanism
#[allow(dead_code)]
#[derive(Clone)]
pub enum RotationMode {
    ExactBytes(usize),
    ExactLines(usize),
    /// do rotation once exceeding size in bytes
    SizeExceeded(usize),
}

/// The main writer structure is used for log rotation
pub struct FileRotation {
    basename: PathBuf,
    count: usize,
    file: Option<Pin<Box<File>>>,
    file_number: usize,
    max_file_number: usize,
    mode: RotationMode,

    //these fields are used by polling
    written: usize,
    rotate_state: RotationState,
}

unsafe impl Send for FileRotation {}
unsafe impl Sync for FileRotation {}

impl FileRotation {
    /// `rotation_mode` specifies the file rotation limits.
    /// Errors if `bytes == 0` or `lines == 0`.
    #[allow(dead_code)]
    pub async fn new<P: AsRef<Path>>(
        path: P,
        rotation_mode: RotationMode,
        max_file_number: usize,
    ) -> Result<Self> {
        if let RotationMode::ExactBytes(bytes) = rotation_mode {
            if bytes == 0 {
                return Err(error::LoggerError::ZeroBytes);
            }
        } else if let RotationMode::ExactLines(lines) = rotation_mode {
            if lines == 0 {
                return Err(error::LoggerError::ZeroLines);
            }
        } else if let RotationMode::SizeExceeded(bytes) = rotation_mode {
            if bytes == 0 {
                return Err(error::LoggerError::ZeroBytes);
            }
        }

        Ok(Self {
            basename: path.as_ref().to_path_buf(),
            count: 0,
            file: Some(Box::pin(
                File::create(&path)
                    .await
                    .map_err(|e| error::LoggerError::IoError(e))?,
            )),
            file_number: 0,
            max_file_number,
            mode: rotation_mode,

            written: 0,
            rotate_state: RotationState::Done,
        })
    }

    fn ready_for_fuse(&mut self) -> io::Result<Pin<&mut File>> {
        if let Some(f) = &mut self.file {
            Ok(f.as_mut())
        } else {
            Err(io::Error::from(io::ErrorKind::NotConnected))
        }
    }

    fn reset(self: &mut Pin<&mut Self>) {
        self.written = 0;
        self.rotate_state = RotationState::Done;
    }

    fn poll_rotate(self: &mut Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        macro_rules! rename {
            () => {
                // drop old files
                self.file = None;
                let basename = self.basename.clone();
                let mut path = self.basename.clone();
                path.set_extension(self.file_number.to_string());
                self.rotate_state =
                    RotationState::PendingRename(Box::pin(fs::rename(basename, path)));
                return self.poll_rotate(ctx);
            };
        }

        match self.rotate_state {
            RotationState::Done => {
                // if called when done, starting rotation
                self.rotate_state = RotationState::PendingFlush;
                self.poll_rotate(ctx)
            }
            RotationState::PendingFlush => match self.file {
                None => {
                    rename!();
                }
                Some(_) => match self.ready_for_fuse()?.poll_flush(ctx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        self.rotate_state = RotationState::Done;
                        Poll::Ready(Err(e))
                    }
                    Poll::Ready(Ok(())) => {
                        rename!();
                    }
                },
            },
            RotationState::PendingRename(ref mut rename_future) => {
                match rename_future.as_mut().poll(ctx) {
                    Poll::Pending => Poll::Pending,

                    // ignore rename errors
                    // as long as creation still succeeds, continue logging
                    Poll::Ready(Err(_)) | Poll::Ready(Ok(())) => {
                        let basename = self.basename.clone();
                        self.rotate_state =
                            RotationState::PendingCreate(Box::pin(File::create(basename)));
                        self.poll_rotate(ctx)
                    }
                }
            }
            RotationState::PendingCreate(ref mut create_future) => {
                match create_future.as_mut().poll(ctx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        self.rotate_state = RotationState::Done;
                        Poll::Ready(Err(e))
                    }
                    Poll::Ready(Ok(file)) => {
                        self.file = Some(Box::pin(file));
                        self.file_number = (self.file_number + 1) % (self.max_file_number + 1);
                        self.count = 0;
                        self.rotate_state = RotationState::Done;
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }

    fn poll_write_bytes(
        self: &mut Pin<&mut Self>,
        ctx: &mut Context<'_>,
        complete_buf: &[u8],
        bytes: usize,
    ) -> Poll<io::Result<bool>> {
        let buf_to_write = &complete_buf[self.written..];
        let (subbuf, should_rotate) = if self.count + buf_to_write.len() > bytes {
            // got more to write than allowed?
            let bytes_left = bytes - self.count;
            (&buf_to_write[..bytes_left], true)
        } else {
            (buf_to_write, false)
        };

        match self.ready_for_fuse() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(file) => match file.poll_write(ctx, subbuf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(w)) => {
                    self.written += w;
                    self.count += w;
                    Poll::Ready(Ok(should_rotate))
                }
            },
        }
    }

    fn poll_write_bytes_exceeded(
        self: &mut Pin<&mut Self>,
        cx: &mut Context<'_>,
        complete_buf: &[u8],
        bytes: usize,
    ) -> Poll<io::Result<bool>> {
        let buf_to_write = &complete_buf[self.written..];

        match self.ready_for_fuse() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(file) => match file.poll_write(cx, buf_to_write) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(w)) => {
                    self.written += w;
                    self.count += w;
                    Poll::Ready(Ok(self.count > bytes))
                }
            },
        }
    }

    fn poll_write_lines(
        self: &mut Pin<&mut Self>,
        ctx: &mut Context<'_>,
        complete_buf: &[u8],
        lines: usize,
    ) -> Poll<io::Result<bool>> {
        let buf_to_write = &complete_buf[self.written..];
        let sub_buf = if let Some((idx, _)) = buf_to_write
            .iter()
            .enumerate()
            .find(|(_, byte)| *byte == &b'\n')
        {
            &buf_to_write[..idx + 1]
        } else {
            buf_to_write
        };

        match self.ready_for_fuse() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(file) => match file.poll_write(ctx, sub_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(w)) => {
                    self.written += w;
                    self.count += 1;
                    Poll::Ready(Ok(self.count >= lines))
                }
            },
        }
    }
}

impl AsyncWrite for FileRotation {
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // This macro generates a block to call poll_rotate and handle the immediate response
        macro_rules! rotate {
            () => {
                match self.poll_rotate(ctx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        self.reset();
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Ok(())) => return self.poll_write(ctx, buf),
                }
            };
        }

        // handle waiting on a rotation future
        match self.rotate_state {
            RotationState::Done => {}
            _ => rotate!(),
        }

        // if we don't have a file, rotate it
        if self.file.is_none() {
            rotate!();
        }

        // If its done, then finish and make it ready
        if buf.len() == self.written {
            let w = self.written;
            self.reset();
            return Poll::Ready(Ok(w));
        }

        let poll_write_result = match self.mode {
            RotationMode::ExactBytes(bytes) => self.poll_write_bytes(ctx, buf, bytes),
            RotationMode::ExactLines(lines) => self.poll_write_lines(ctx, buf, lines),
            RotationMode::SizeExceeded(bytes) => self.poll_write_bytes_exceeded(ctx, buf, bytes),
        };

        match poll_write_result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.reset();
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(false)) => self.poll_write(ctx, buf),
            Poll::Ready(Ok(true)) => {
                rotate!()
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.ready_for_fuse() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(file) => file.poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.ready_for_fuse() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(file) => file.poll_shutdown(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn zero_bytes() {
        let zerobyteserr =
            FileRotation::new("/tmp/async_zero_bytes.log", RotationMode::ExactBytes(0), 0).await;
        match zerobyteserr {
            Err(error::LoggerError::ZeroBytes) => {}
            _ => panic!("Expected ZeroBytes error"),
        };
    }

    #[tokio::test]
    async fn zero_lines() {
        let zerolineserr =
            FileRotation::new("/tmp/async_zero_lines.log", RotationMode::ExactLines(0), 0).await;
        match zerolineserr {
            Err(error::LoggerError::ZeroLines) => {}
            _ => panic!("Expected ZeroLines error"),
        };
    }

    #[tokio::test]
    async fn zero_bytes_exceeded() {
        let zerobyteserr = FileRotation::new(
            "/tmp/async_zero_bytes.log",
            RotationMode::SizeExceeded(0),
            0,
        )
        .await;
        match zerobyteserr {
            Err(error::LoggerError::ZeroBytes) => {}
            _ => panic!("Expected ZeroBytes error"),
        };
    }

    #[tokio::test]
    async fn rotate_on_deleted_dir() {
        let _ = fs::remove_dir_all("/tmp/async_rotate").await;
        fs::create_dir("/tmp/async_rotate").await.unwrap();

        let mut rot =
            FileRotation::new("/tmp/async_rotate/test.log", RotationMode::ExactLines(1), 0)
                .await
                .unwrap();
        rot.write(b"a\n").await.unwrap();
        assert_eq!(
            "",
            fs::read_to_string("/tmp/async_rotate/test.log")
                .await
                .unwrap()
        );
        assert_eq!(
            "a\n",
            fs::read_to_string("/tmp/async_rotate/test.log.0")
                .await
                .unwrap()
        );

        fs::remove_dir_all("/tmp/async_rotate").await.unwrap();

        assert!(rot.write(b"b\n").await.is_err());

        assert!(rot.flush().await.is_err());
        assert!(fs::read_dir("/tmp/async_rotate").await.is_err());

        fs::create_dir("/tmp/async_rotate").await.unwrap();

        rot.write(b"c\n").await.unwrap();
        assert_eq!(
            "",
            fs::read_to_string("/tmp/async_rotate/test.log")
                .await
                .unwrap()
        );

        rot.write(b"d\n").await.unwrap();
        assert_eq!(
            "",
            fs::read_to_string("/tmp/async_rotate/test.log")
                .await
                .unwrap()
        );
        assert_eq!(
            "d\n",
            fs::read_to_string("/tmp/async_rotate/test.log.0")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn write_record_until_bytes_exceeded() {
        let _ = fs::remove_dir_all("/tmp/async_exceeded_bytes").await;
        fs::create_dir("/tmp/async_exceeded_bytes").await.unwrap();

        let mut rot = FileRotation::new(
            "/tmp/async_exceeded_bytes/test.log",
            RotationMode::SizeExceeded(1),
            1,
        )
        .await
        .unwrap();

        rot.write(b"This is exceeded byte data already")
            .await
            .unwrap();
        rot.flush().await.unwrap();
        assert!(Path::new("/tmp/async_exceeded_bytes/test.log.0").exists());
        // its exist yet - because the complete record was written single-shot
        assert!(!Path::new("/tmp/async_exceeded_bytes/test.log.1").exists());

        // This should create the 2nd file
        rot.write(b"This is exceeded byte data already - 2nd time")
            .await
            .unwrap();
        rot.flush().await.unwrap();
        assert!(Path::new("/tmp/async_exceeded_bytes/test.log.1").exists());

        fs::remove_dir_all("/tmp/async_exceeded_bytes")
            .await
            .unwrap();
    }
}
