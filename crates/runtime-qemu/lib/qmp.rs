//! Minimal QEMU Machine Protocol client.

use std::{net::SocketAddr, time::Duration};

use agent_sandbox_runtime::{Result, RuntimeError};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, tcp::OwnedWriteHalf},
    time::timeout,
};

pub(crate) async fn execute(
    address: SocketAddr,
    command: &str,
    connect_timeout: Duration,
) -> Result<Value> {
    let stream = timeout(connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| {
            qmp_error(
                "connect to QMP",
                format!("timed out connecting to {address}"),
            )
        })?
        .map_err(|error| qmp_error("connect to QMP", format!("{address}: {error}")))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let greeting = read_message(&mut reader).await?;
    if greeting.get("QMP").is_none() {
        return Err(qmp_error(
            "negotiate QMP",
            format!("unexpected greeting: {greeting}"),
        ));
    }
    send(&mut writer, &json!({"execute": "qmp_capabilities"})).await?;
    read_response(&mut reader, "qmp_capabilities").await?;

    send(&mut writer, &json!({"execute": command})).await?;
    read_response(&mut reader, command).await
}

async fn send(writer: &mut OwnedWriteHalf, value: &Value) -> Result<()> {
    let mut data = serde_json::to_vec(value).map_err(|error| qmp_error("encode QMP", error))?;
    data.push(b'\n');
    writer
        .write_all(&data)
        .await
        .map_err(|error| qmp_error("write QMP", error))
}

async fn read_message(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Result<Value> {
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .map_err(|error| qmp_error("read QMP", error))?;
        if read == 0 {
            return Err(qmp_error("read QMP", "connection closed"));
        }
        if line.trim().is_empty() {
            continue;
        }
        return serde_json::from_str(&line).map_err(|error| qmp_error("decode QMP", error));
    }
}

async fn read_response(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    command: &str,
) -> Result<Value> {
    loop {
        let message = read_message(reader).await?;
        if let Some(value) = message.get("return") {
            return Ok(value.clone());
        }
        if let Some(error) = message.get("error") {
            return Err(qmp_error(
                "execute QMP command",
                format!("{command}: {error}"),
            ));
        }
        // Asynchronous events may arrive between a request and its response.
    }
}

fn qmp_error(operation: &'static str, error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Backend {
        operation,
        message: error.to_string(),
    }
}
