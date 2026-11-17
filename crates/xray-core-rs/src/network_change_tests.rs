//! [`Core::network_changed`]: what it resets, and the connection it warms.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// A SOCKS5 server that echoes every tunnel and counts its connections.
async fn socks_echo_server() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut greeting = [0; 2];
                stream.read_exact(&mut greeting).await?;
                let mut methods = vec![0; usize::from(greeting[1])];
                stream.read_exact(&mut methods).await?;
                stream.write_all(&[5, 0]).await?;
                let mut request = [0; 4];
                stream.read_exact(&mut request).await?;
                let address_len = match request[3] {
                    1 => 4,
                    4 => 16,
                    _ => usize::from(stream.read_u8().await?),
                };
                let mut rest = vec![0; address_len + 2];
                stream.read_exact(&mut rest).await?;
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    (address, accepted, task)
}

/// One echo through the core's SOCKS inbound at `proxy`.
async fn echo_through(proxy: SocketAddr, payload: &[u8]) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    stream
        .write_all(&[5, 1, 0, 1, 192, 0, 2, 10, 0, 80])
        .await
        .unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "the tunnel opened");
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

fn socks_core(server: SocketAddr, stream: &str) -> Core {
    let raw = format!(
        r#"{{"inbounds":[{{"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":0}}],
            "outbounds":[{{"tag":"proxy","protocol":"socks",
                           "settings":{{"servers":[{{"address":"{}","port":{}}}]}}{stream}}}]}}"#,
        server.ip(),
        server.port()
    );
    Core::new(xray_config::parse_xray_json(&raw).unwrap().config).unwrap()
}

fn prewarm_finished(core: &Core) -> Option<bool> {
    core.prewarm
        .lock()
        .unwrap()
        .as_ref()
        .map(tokio::task::AbortHandle::is_finished)
}

/// The flow after a network change rides the connection the change opened
/// ahead to the proxy: the server sees no second connection for it.
#[tokio::test]
async fn the_first_flow_after_a_change_takes_the_warmed_connection() {
    let (server, accepted, server_task) = socks_echo_server().await;
    let mut core = socks_core(server, "");
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    timeout(Duration::from_secs(10), async {
        echo_through(proxy, b"before").await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        let report = core.network_changed().await;
        assert!(report.prewarm_started, "{report:?}");
        while accepted.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        while prewarm_finished(&core) != Some(true) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        echo_through(proxy, b"after the change").await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the flow took the connection opened ahead"
        );
        // The one after it dials as usual.
        echo_through(proxy, b"and the next").await;
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    })
    .await
    .expect("the flows work across a network change");
    core.stop().await.unwrap();
    server_task.abort();
}

/// A connection held ahead and not taken within its lifetime is dropped,
/// and the next flow dials a fresh one.
#[tokio::test]
async fn a_warmed_connection_nobody_took_expires() {
    let (server, accepted, server_task) = socks_echo_server().await;
    let mut core = socks_core(server, "");
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    timeout(Duration::from_secs(10), async {
        assert!(core.network_changed().await.prewarm_started);
        while prewarm_finished(&core) != Some(true) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        tokio::time::sleep(outbound::WARM_CARRIER_LIFETIME + Duration::from_millis(100)).await;
        echo_through(proxy, b"late").await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the stale one was not used"
        );
    })
    .await
    .unwrap();
    core.stop().await.unwrap();
    server_task.abort();
}

/// Warming a proxy that never answers its TLS handshake gives up after
/// `PREWARM_TIMEOUT`, and the next change cancels the one before it.
#[tokio::test(start_paused = true)]
async fn warming_is_bounded_and_the_next_change_cancels_it() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = silent.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            streams.push(stream);
        }
    });
    let mut core = socks_core(
        address,
        r#","streamSettings":{"security":"tls","tlsSettings":{"serverName":"proxy.test"}}"#,
    );
    core.start().await.unwrap();

    let started = tokio::time::Instant::now();
    assert!(core.network_changed().await.prewarm_started);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "it does not wait"
    );
    tokio::time::sleep(PREWARM_TIMEOUT - Duration::from_millis(100)).await;
    assert_eq!(
        prewarm_finished(&core),
        Some(false),
        "still waiting for the server"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        prewarm_finished(&core),
        Some(true),
        "bounded by the timeout"
    );

    assert!(core.network_changed().await.prewarm_started);
    let first = core.prewarm.lock().unwrap().take().unwrap();
    *core.prewarm.lock().unwrap() = Some(first.clone());
    assert!(core.network_changed().await.prewarm_started);
    tokio::task::yield_now().await;
    assert!(first.is_finished(), "the next change cancelled it");
    core.stop().await.unwrap();
    assert!(core.prewarm.lock().unwrap().is_none(), "a stop cancels it");
    held.abort();
}

/// A change on a core that is not running resets what it can and warms
/// nothing; one on a stopped core neither.
#[tokio::test]
async fn a_change_before_the_start_warms_nothing() {
    let (server, _, server_task) = socks_echo_server().await;
    let mut core = socks_core(server, "");
    let report = core.network_changed().await;
    assert_eq!(report, NetworkChangeReport::default());
    core.start().await.unwrap();
    core.stop().await.unwrap();
    assert!(!core.network_changed().await.prewarm_started);
    server_task.abort();
}
