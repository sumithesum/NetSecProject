use std::env;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = "127.0.0.1:8080";
    let default_target = env::args().nth(1);

    let listener = TcpListener::bind(listen_addr).await?;
    println!();
    println!("[*] TLS Handshake Harvester running on {}", listen_addr);
    if let Some(target) = &default_target {
        println!("[*] Default target: {}", target);
    }
    println!("[*] Așteaptă TLS ClientHello-uri necriptate...\n");
    println!("[*] Exemplu de utilizare: curl -x http://127.0.0.1:8080 https://www.google.com\n");

    loop {
        let (client, client_addr) = listener.accept().await?;
        let default_target = default_target.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, default_target, client_addr).await {
                eprintln!("[!] Eroare la conexiune {}: {}", client_addr, err);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    default_target: Option<String>,
    client_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut read_buf = vec![0u8; 4096];
    let mut initial_data = Vec::new();

    loop {
        let n = client.read(&mut read_buf).await?;
        if n == 0 {
            return Ok(());
        }

        initial_data.extend_from_slice(&read_buf[..n]);
        if initial_data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }

        if initial_data.len() > 16 * 1024 {
            break;
        }
    }

    let (server_addr, is_connect, tls_payload) = if let Some(connect_target) = parse_connect_target(&initial_data) {
        (connect_target, true, extract_tls_payload_after_connect(&initial_data))
    } else if let Some(target) = default_target {
        (target, false, Some(initial_data.clone()))
    } else {
        return Err("No target host provided and no CONNECT request received".into());
    };

    println!("[*] Client {} -> {}", client_addr, server_addr);
    let mut server = TcpStream::connect(&server_addr).await?;

    if is_connect {
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    }

    if let Some(payload) = tls_payload {
        intercept_and_forward(&mut client, &mut server, Some(payload), client_addr).await?;
    } else {
        intercept_and_forward(&mut client, &mut server, None, client_addr).await?;
    }

    Ok(())
}

async fn intercept_and_forward(
    client: &mut TcpStream,
    server: &mut TcpStream,
    initial_payload: Option<Vec<u8>>,
    client_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first_payload = initial_payload.unwrap_or_default();
    let mut temp_buf = [0u8; 4096];

    if first_payload.is_empty() {
        let n = client.read(&mut temp_buf).await?;
        if n == 0 {
            return Ok(());
        }
        first_payload.extend_from_slice(&temp_buf[..n]);
    }

    if first_payload.len() >= 6 && first_payload[0] == 0x16 && first_payload[5] == 0x01 {
        println!("[!] INTERCEPTAT: TLS ClientHello necriptat de la {}", client_addr);
        println!("[+] Se colectează date de handshake ({} bytes)", first_payload.len());

        if let Some(client_hello) = parse_tls_client_hello(&first_payload) {
            if let Some(sni) = client_hello.sni {
                println!("[+] SNI: {}", sni);
            }

            if !client_hello.supported_versions.is_empty() {
                let version_names: Vec<String> = client_hello
                    .supported_versions
                    .iter()
                    .map(|v| version_name(*v).to_string())
                    .collect();
                println!("[+] Supported versions: {}", version_names.join(", "));
            }

            if client_hello.key_shares.is_empty() {
                println!("[!] Nu s-a găsit extensia key_share în ClientHello.");
                println!("    Acest client probabil nu folosește TLS 1.3 sau folosește o sesiune PSK fără key_share.");
                println!("    Pentru un demo complet, folosește un client TLS 1.3 explicit, de exemplu:\n        curl --tlsv1.3 -x http://127.0.0.1:8080 https://www.google.com\n");
            } else {
                for entry in client_hello.key_shares.iter() {
                    println!(
                        "[+] key_share group=0x{:04x} ({}) public_bytes={} bytes",
                        entry.group,
                        group_name(entry.group),
                        entry.payload.len()
                    );
                    println!("    {}", hex::encode(&entry.payload));
                }
            }
            println!(
                "[+] În practică, atacatorul stochează aceste puncte publice pentru decriptare ulterioară.\n"
            );
        } else {
            let sample = &first_payload[..first_payload.len().min(64)];
            println!(
                "[+] Exemplu de date salvate (primele {} bytes): {}",
                sample.len(),
                hex::encode(sample)
            );
            println!(
                "[+] Nu s-a putut parsa complet ClientHello; s-a salvat payload brut.\n"
            );
        }
    }

    server.write_all(&first_payload).await?;

    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = server.split();

    let c2s = tokio::io::copy(&mut client_read, &mut server_write);
    let s2c = tokio::io::copy(&mut server_read, &mut client_write);

    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
    }

    Ok(())
}

fn parse_connect_target(data: &[u8]) -> Option<String> {
    let header = String::from_utf8_lossy(data);
    let mut lines = header.lines();
    let first = lines.next()?;
    if !first.starts_with("CONNECT ") {
        return None;
    }

    let mut parts = first.split_whitespace();
    parts.next()?;
    let host_port = parts.next()?;
    Some(host_port.to_string())
}

fn extract_tls_payload_after_connect(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(pos) = data.windows(4).position(|window| window == b"\r\n\r\n") {
        let payload = data[pos + 4..].to_vec();
        if payload.is_empty() {
            None
        } else {
            Some(payload)
        }
    } else {
        None
    }
}

struct KeyShareEntry {
    group: u16,
    payload: Vec<u8>,
}

struct ClientHelloInfo {
    sni: Option<String>,
    supported_versions: Vec<u16>,
    key_shares: Vec<KeyShareEntry>,
}

fn parse_tls_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len || record_len < 4 {
        return None;
    }

    if data[5] != 0x01 {
        return None;
    }

    let hs_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    let hs_start = 9;
    if record_len < 4 + hs_len || data.len() < hs_start + hs_len {
        return None;
    }

    let mut pos = hs_start;
    if pos + 2 + 32 > data.len() {
        return None;
    }
    pos += 2;
    pos += 32;

    if pos + 1 > data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;
    if pos + session_id_len > data.len() {
        return None;
    }
    pos += session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > data.len() {
        return None;
    }
    pos += cipher_suites_len;

    if pos + 1 > data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1;
    if pos + compression_len > data.len() {
        return None;
    }
    pos += compression_len;

    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + extensions_len > data.len() {
        return None;
    }

    let mut sni = None;
    let mut supported_versions = Vec::new();
    let mut key_shares = Vec::new();
    let mut extensions = &data[pos..pos + extensions_len];
    while extensions.len() >= 4 {
        let ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        extensions = &extensions[4..];
        if extensions.len() < ext_len {
            return None;
        }

        let ext_data = &extensions[..ext_len];
        if ext_type == 0x0000 {
            if let Some(hostname) = parse_sni(ext_data) {
                sni = Some(hostname);
            }
        } else if ext_type == 0x002b {
            supported_versions = parse_supported_versions(ext_data);
        } else if ext_type == 0x0033 {
            if let Some(shares) = parse_key_share(ext_data) {
                key_shares.extend(shares);
            }
        }

        extensions = &extensions[ext_len..];
    }

    Some(ClientHelloInfo { sni, supported_versions, key_shares })
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut rest = &data[2..];
    if rest.len() < list_len {
        return None;
    }

    while rest.len() >= 3 {
        let name_type = rest[0];
        let name_len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        rest = &rest[3..];
        if rest.len() < name_len {
            return None;
        }
        if name_type == 0 {
            let name = String::from_utf8_lossy(&rest[..name_len]);
            return Some(name.into_owned());
        }
        rest = &rest[name_len..];
    }
    None
}

fn parse_key_share(data: &[u8]) -> Option<Vec<KeyShareEntry>> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut rest = &data[2..];
    if rest.len() < list_len {
        return None;
    }

    let mut entries = Vec::new();
    while rest.len() >= 4 {
        let group = u16::from_be_bytes([rest[0], rest[1]]);
        let share_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < share_len {
            return None;
        }
        entries.push(KeyShareEntry { group, payload: rest[..share_len].to_vec() });
        rest = &rest[share_len..];
    }
    Some(entries)
}

fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    if data.len() < 1 {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    let mut versions = Vec::new();
    let mut rest = &data[1..];
    if rest.len() < list_len {
        return Vec::new();
    }
    while rest.len() >= 2 {
        versions.push(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
    }
    versions
}

fn version_name(version: u16) -> &'static str {
    match version {
        0x0304 => "TLS1.3",
        0x0303 => "TLS1.2",
        0x0302 => "TLS1.1",
        0x0301 => "TLS1.0",
        0x0300 => "SSL3.0",
        _ => "unknown",
    }
}

fn group_name(group: u16) -> &'static str {
    match group {
        0x001d => "x25519",
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001e => "x448",
        _ => "unknown",
    }
}
