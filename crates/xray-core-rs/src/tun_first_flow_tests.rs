//! The runtime log breaks the first TCP flows after a start down.

use super::idle_tests::{receive_segment, tcp_segment, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN};
use super::*;
use std::net::SocketAddrV4;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// One exchange over a TUN TCP flow to `server`, from `client_sequence`.
async fn exchange(tun: &TunEndpoint, server: SocketAddrV4, client_sequence: u32) {
    let mut sequence = client_sequence;
    tun.push_inbound(tcp_segment(server, sequence, 0, TCP_SYN, &[]))
        .await
        .unwrap();
    sequence += 1;
    let (_, server_syn, _) = receive_segment(tun, |flags, _| {
        flags & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK
    })
    .await;
    let acknowledged = server_syn.wrapping_add(1);
    tun.push_inbound(tcp_segment(server, sequence, acknowledged, TCP_ACK, &[]))
        .await
        .unwrap();
    tun.push_inbound(tcp_segment(
        server,
        sequence,
        acknowledged,
        TCP_PSH | TCP_ACK,
        b"ping",
    ))
    .await
    .unwrap();
    let (_, _, echoed) =
        receive_segment(tun, |flags, data| flags & TCP_FIN == 0 && !data.is_empty()).await;
    assert_eq!(echoed, b"ping");
}

#[tokio::test]
async fn the_first_flow_after_a_start_gets_a_timing_line() {
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let SocketAddr::V4(server) = echo.local_addr().unwrap() else {
        unreachable!("bound to IPv4");
    };
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut buffer = [0; 64];
        loop {
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                return;
            }
        }
    });
    let dir = std::env::temp_dir().join(format!(
        "xray-first-flow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let raw = r#"{"inbounds":[{"tag":"tun-in","protocol":"tun"}],
                  "outbounds":[{"protocol":"freedom","tag":"direct"}]}"#;
    let config = xray_config::parse_xray_json(raw).unwrap().config;
    let mut core = crate::Core::new(config).unwrap();
    core.set_runtime_logger(
        crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir)).unwrap(),
    );
    core.start().await.unwrap();

    timeout(Duration::from_secs(10), exchange(core.tun(), server, 1_000))
        .await
        .expect("the TCP flow works");
    core.stop().await.unwrap();
    // The log's writer flushes as the last logger goes.
    drop(core);
    echo_task.abort();

    let log = std::fs::read_to_string(dir.join("xray-error.log")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let line = log
        .lines()
        .find(|line| line.contains("First flow 1/8 after start"))
        .unwrap_or_else(|| panic!("no first-flow line in {log}"));
    assert!(line.contains("[info]") || line.contains("info"), "{line}");
    assert!(line.contains("outbound=direct"), "{line}");
    assert!(line.contains("target=<redacted-ip>:"), "{line}");
    for phase in ["accepted=+", "route=", "resolve=", "dial=", "firstByte="] {
        assert!(line.contains(phase), "{phase} missing from {line}");
    }
    assert!(!line.contains("firstByte=-"), "{line}");
}
