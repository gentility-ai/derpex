use std::{env, net::Ipv4Addr, time::Duration};

use tokio::time::timeout;
use ts_derp::{Client, IpUsage, ServerConnInfo, TlsValidationConfig};
use ts_keys::NodeKeyPair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::args()
        .nth(1)
        .ok_or("usage: derpex-rust-smoke PORT")?
        .parse::<u16>()?;

    let server = ServerConnInfo {
        hostname: "localhost".to_owned(),
        ipv4: IpUsage::FixedAddr(Ipv4Addr::LOCALHOST),
        ipv6: IpUsage::Disable,
        tls_validation_config: TlsValidationConfig::InsecureForTests,
        https_port: port,
        stun_port: None,
        stun_only: false,
        supports_port_80: false,
    };

    let first_key = NodeKeyPair::new();
    let second_key = NodeKeyPair::new();
    let first = Client::connect([&server], &first_key).await?;
    let second = Client::connect([&server], &second_key).await?;

    assert_relay(&first, &first_key, &second, &second_key, b"rust-to-derpex").await?;
    assert_relay(&second, &second_key, &first, &first_key, b"derpex-to-rust").await?;

    println!("official Rust clients authenticated and relayed both directions");
    Ok(())
}

async fn assert_relay(
    sender: &ts_derp::DefaultClient,
    sender_key: &NodeKeyPair,
    receiver: &ts_derp::DefaultClient,
    receiver_key: &NodeKeyPair,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    sender.send_one(receiver_key.public, payload).await?;

    let (source, packet) = timeout(Duration::from_secs(2), receiver.recv_one()).await??;
    if source != sender_key.public || packet.as_ref() != payload {
        return Err("relayed source or payload did not match".into());
    }

    Ok(())
}
