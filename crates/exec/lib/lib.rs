//! Bounded streaming output forwarding.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use agent_sandbox_runtime::{ExecEvent, ExecStream, OutputStream};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::io::{AsyncWriteExt, stderr, stdout};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Output-forwarding error.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// Runtime stream failed.
    #[error(transparent)]
    Runtime(#[from] agent_sandbox_runtime::RuntimeError),
    /// Host output stream failed.
    #[error("cannot write command output: {0}")]
    Io(#[from] std::io::Error),
    /// The runtime stream ended without a terminal event.
    #[error("runtime output stream ended without an exit event")]
    MissingExit,
}

/// Stable CLI output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Raw stdout and stderr on their corresponding host streams.
    Text,
    /// All output and control events as JSON Lines on stdout.
    JsonLines,
    /// Retain only bounded tails for a final JSON object.
    Capture,
}

/// Completion summary with bounded diagnostic tails.
#[derive(Debug, Clone)]
pub struct ExecSummary {
    /// Guest exit code.
    pub exit_code: i32,
    /// Bounded stdout tail.
    pub stdout_tail: Vec<u8>,
    /// Whether earlier stdout bytes were discarded.
    pub stdout_truncated: bool,
    /// Bounded stderr tail.
    pub stderr_tail: Vec<u8>,
    /// Whether earlier stderr bytes were discarded.
    pub stderr_truncated: bool,
}

#[derive(Debug)]
struct TailBuffer {
    bytes: VecDeque<u8>,
    capacity: usize,
    truncated: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TailBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(capacity.min(64 * 1024)),
            capacity,
            truncated: false,
        }
    }

    fn push(&mut self, data: &[u8]) {
        if self.capacity == 0 {
            self.truncated |= !data.is_empty();
            return;
        }
        if data.len() >= self.capacity {
            self.bytes.clear();
            self.bytes.extend(
                data[data.len().saturating_sub(self.capacity)..]
                    .iter()
                    .copied(),
            );
            self.truncated = true;
            return;
        }
        let overflow = self
            .bytes
            .len()
            .saturating_add(data.len())
            .saturating_sub(self.capacity);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.truncated = true;
        }
        self.bytes.extend(data.iter().copied());
    }

    fn into_parts(self) -> (Vec<u8>, bool) {
        (self.bytes.into(), self.truncated)
    }

    fn mark_truncated(&mut self) {
        self.truncated = true;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Forward all events while retaining only bounded stdout/stderr tails.
pub async fn forward(
    mut stream: ExecStream,
    format: OutputFormat,
    tail_capacity: usize,
) -> Result<ExecSummary, OutputError> {
    let mut out_tail = TailBuffer::new(tail_capacity);
    let mut err_tail = TailBuffer::new(tail_capacity);
    let mut exit_code = None;
    let mut host_stdout = stdout();
    let mut host_stderr = stderr();

    while let Some(event) = stream.recv().await {
        match event? {
            ExecEvent::Started { pid } => {
                if format == OutputFormat::JsonLines {
                    write_json(
                        &mut host_stdout,
                        serde_json::json!({
                            "type": "exec.started",
                            "pid": pid,
                        }),
                    )
                    .await?;
                }
            }
            ExecEvent::Stdout(data) => {
                out_tail.push(&data);
                match format {
                    OutputFormat::Text => host_stdout.write_all(&data).await?,
                    OutputFormat::JsonLines => {
                        write_json(
                            &mut host_stdout,
                            serde_json::json!({
                                "type": "exec.stdout",
                                "data": String::from_utf8_lossy(&data),
                                "data_base64": STANDARD.encode(&data),
                            }),
                        )
                        .await?;
                    }
                    OutputFormat::Capture => {}
                }
            }
            ExecEvent::Stderr(data) => {
                err_tail.push(&data);
                match format {
                    OutputFormat::Text => host_stderr.write_all(&data).await?,
                    OutputFormat::JsonLines => {
                        write_json(
                            &mut host_stdout,
                            serde_json::json!({
                                "type": "exec.stderr",
                                "data": String::from_utf8_lossy(&data),
                                "data_base64": STANDARD.encode(&data),
                            }),
                        )
                        .await?;
                    }
                    OutputFormat::Capture => {}
                }
            }
            ExecEvent::OutputTruncated {
                stream,
                dropped_bytes,
            } => {
                match stream {
                    OutputStream::Stdout => out_tail.mark_truncated(),
                    OutputStream::Stderr => err_tail.mark_truncated(),
                }
                match format {
                    OutputFormat::Text => {
                        host_stderr
                            .write_all(
                                format!(
                                    "\n[asbx: discarded {dropped_bytes} bytes from guest {} to preserve bounded host memory]\n",
                                    match stream {
                                        OutputStream::Stdout => "stdout",
                                        OutputStream::Stderr => "stderr",
                                    }
                                )
                                .as_bytes(),
                            )
                            .await?;
                    }
                    OutputFormat::JsonLines => {
                        write_json(
                            &mut host_stdout,
                            serde_json::json!({
                                "type": "exec.output_truncated",
                                "stream": match stream {
                                    OutputStream::Stdout => "stdout",
                                    OutputStream::Stderr => "stderr",
                                },
                                "dropped_bytes": dropped_bytes,
                            }),
                        )
                        .await?;
                    }
                    OutputFormat::Capture => {}
                }
            }
            ExecEvent::TimedOut {
                after,
                sandbox_terminated,
            } => {
                let message = format!(
                    "guest command timed out after {after:?}{}",
                    if sandbox_terminated {
                        "; the sandbox was terminated after process-level cleanup did not finish"
                    } else {
                        ""
                    }
                );
                err_tail.push(message.as_bytes());
                match format {
                    OutputFormat::Text => {
                        host_stderr.write_all(message.as_bytes()).await?;
                        host_stderr.write_all(b"\n").await?;
                    }
                    OutputFormat::JsonLines => {
                        write_json(
                            &mut host_stdout,
                            serde_json::json!({
                                "type": "exec.timed_out",
                                "timeout_ms": after.as_millis(),
                                "sandbox_terminated": sandbox_terminated,
                            }),
                        )
                        .await?;
                    }
                    OutputFormat::Capture => {}
                }
                exit_code = Some(124);
                break;
            }
            ExecEvent::Exited { code } => {
                exit_code = Some(code);
                if format == OutputFormat::JsonLines {
                    write_json(
                        &mut host_stdout,
                        serde_json::json!({
                            "type": "exec.exit",
                            "code": code,
                        }),
                    )
                    .await?;
                }
                break;
            }
            ExecEvent::Failed(message) => {
                err_tail.push(message.as_bytes());
                if format == OutputFormat::JsonLines {
                    write_json(
                        &mut host_stdout,
                        serde_json::json!({
                            "type": "exec.failed",
                            "message": message,
                        }),
                    )
                    .await?;
                } else {
                    host_stderr.write_all(message.as_bytes()).await?;
                    host_stderr.write_all(b"\n").await?;
                }
                exit_code = Some(127);
                break;
            }
        }
    }

    host_stdout.flush().await?;
    host_stderr.flush().await?;
    let (stdout_tail, stdout_truncated) = out_tail.into_parts();
    let (stderr_tail, stderr_truncated) = err_tail.into_parts();
    Ok(ExecSummary {
        exit_code: exit_code.ok_or(OutputError::MissingExit)?,
        stdout_tail,
        stdout_truncated,
        stderr_tail,
        stderr_truncated,
    })
}

async fn write_json(
    output: &mut tokio::io::Stdout,
    value: serde_json::Value,
) -> Result<(), std::io::Error> {
    let mut line = serde_json::to_vec(&value).expect("JSON value serialization cannot fail");
    line.push(b'\n');
    output.write_all(&line).await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_discards_old_bytes() {
        let mut tail = TailBuffer::new(5);
        tail.push(b"abc");
        tail.push(b"defg");
        let (bytes, truncated) = tail.into_parts();
        assert_eq!(bytes, b"cdefg");
        assert!(truncated);
    }

    #[test]
    fn oversized_chunk_keeps_only_its_tail() {
        let mut tail = TailBuffer::new(3);
        tail.push(b"abcdef");
        let (bytes, truncated) = tail.into_parts();
        assert_eq!(bytes, b"def");
        assert!(truncated);
    }
}
