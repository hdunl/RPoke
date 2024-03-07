use clap::{arg, command};
use futures::stream::{self, StreamExt};
use regex::Regex;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;

#[derive(Serialize)]
struct ScanResult {
    target: String,
    port: u16,
    status: String,
    service: Option<String>,
    version: Option<String>,
}

async fn scan_port(target: SocketAddr, timeout_ms: u64) -> Option<ScanResult> {
    let timeout_duration = Duration::from_millis(timeout_ms);

    match timeout(timeout_duration, AsyncTcpStream::connect(target)).await {
        Ok(Ok(mut stream)) => {
            let service_probe = match target.port() {
                21 => b"QUIT\r\n".to_vec(),
                22 => b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n".to_vec(),
                25 => b"HELO example.com\r\n".to_vec(),
                53 => b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                80 | 8080 => b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                110 => b"QUIT\r\n".to_vec(),
                143 => b"a1 LOGOUT\r\n".to_vec(),
                443 | 8443 => b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                465 => b"QUIT\r\n".to_vec(),
                993 => b"a1 LOGOUT\r\n".to_vec(),
                995 => b"QUIT\r\n".to_vec(),
                1723 => b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                3306 => b"\x0a\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                3389 => b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec(),
                5432 => b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec(),
                5900 | 5901 => b"RFB 003.008\n".to_vec(),
                6379 => b"PING\r\n".to_vec(),
                _ => Vec::new(),
            };

            let _ = stream.write(&service_probe).await;
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await;

            let response = String::from_utf8_lossy(&buffer);
            let (service, version) = match target.port() {
                21 => ftp_service_detection(&response),
                22 => ssh_service_detection(&response),
                25 => smtp_service_detection(&response),
                53 => dns_service_detection(&response),
                80 | 8080 => http_service_detection(&response),
                110 => pop3_service_detection(&response),
                143 => imap_service_detection(&response),
                443 | 8443 => https_service_detection(&response),
                465 => smtps_service_detection(&response),
                993 => imaps_service_detection(&response),
                995 => pop3s_service_detection(&response),
                1723 => pptp_service_detection(&response),
                3306 => mysql_service_detection(&response),
                3389 => rdp_service_detection(&response),
                5432 => postgres_service_detection(&response),
                5900 | 5901 => vnc_service_detection(&response),
                6379 => redis_service_detection(&response),
                _ => ("Unknown".to_string(), None),
            };

            Some(ScanResult {
                target: target.ip().to_string(),
                port: target.port(),
                status: "open".to_string(),
                service: Some(service),
                version,
            })
        }
        _ => None,
    }
}

fn ftp_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("220") && response.contains("FTP") {
        let version = extract_version(response, r"[\d.]+");
        ("FTP".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn ssh_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("SSH") {
        let version = extract_version(response, r"SSH-\d+\.\d+-[\w.-]+");
        ("SSH".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn smtp_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("220") && response.contains("SMTP") {
        let version = extract_version(response, r"[\d.]+");
        ("SMTP".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn dns_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("\x00\x00") {
        ("DNS".to_string(), None)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn http_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("HTTP") {
        if response.contains("Apache") {
            let version = extract_version(response, r"Apache/[\d.]+");
            ("Apache HTTP".to_string(), version)
        } else if response.contains("nginx") {
            let version = extract_version(response, r"nginx/[\d.]+");
            ("nginx".to_string(), version)
        } else {
            ("HTTP".to_string(), None)
        }
    } else {
        ("Unknown".to_string(), None)
    }
}

fn pop3_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("+OK") && response.contains("POP3") {
        let version = extract_version(response, r"[\d.]+");
        ("POP3".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn imap_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("* OK") && response.contains("IMAP") {
        let version = extract_version(response, r"IMAP\d+[\w.-]+");
        ("IMAP".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn https_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("HTTP") && response.contains("SSL") {
        if response.contains("Apache") {
            let version = extract_version(response, r"Apache/[\d.]+");
            ("Apache HTTPS".to_string(), version)
        } else if response.contains("nginx") {
            let version = extract_version(response, r"nginx/[\d.]+");
            ("nginx (SSL)".to_string(), version)
        } else {
            ("HTTPS".to_string(), None)
        }
    } else {
        ("Unknown".to_string(), None)
    }
}

fn smtps_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("220") && response.contains("SMTPS") {
        let version = extract_version(response, r"[\d.]+");
        ("SMTPS".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn imaps_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("* OK") && response.contains("IMAP") && response.contains("SSL") {
        let version = extract_version(response, r"IMAP\d+[\w.-]+");
        ("IMAPS".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn pop3s_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("+OK") && response.contains("POP3") && response.contains("SSL") {
        let version = extract_version(response, r"[\d.]+");
        ("POP3S".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn pptp_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("\x00\x00\x00\x00") {
        ("PPTP".to_string(), None)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn mysql_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("\x0a\x00\x00\x01") {
        let version = extract_version(response, r"\d+\.\d+\.\d+");
        ("MySQL".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn rdp_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("\x03\x00\x00\x13") {
        ("RDP".to_string(), None)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn postgres_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("\x00\x00\x00\x08") {
        let version = extract_version(response, r"\d+\.\d+");
        ("PostgreSQL".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn vnc_service_detection(response: &str) -> (String, Option<String>) {
    if response.starts_with("RFB ") {
        let version = extract_version(response, r"\d+\.\d+");
        ("VNC".to_string(), version)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn redis_service_detection(response: &str) -> (String, Option<String>) {
    if response.contains("+PONG") {
        ("Redis".to_string(), None)
    } else {
        ("Unknown".to_string(), None)
    }
}

fn extract_version(response: &str, pattern: &str) -> Option<String> {
    let regex = Regex::new(pattern).unwrap();
    regex
        .captures(response)
        .and_then(|captures| captures.get(0))
        .map(|v| v.as_str().to_string())
}

async fn scan_ports(target: IpAddr, start_port: u16, end_port: u16, num_threads: usize, timeout_ms: u64) -> Vec<ScanResult> {
    let ports: Vec<u16> = (start_port..=end_port).collect();
    let total_ports = ports.len() as u16;

    let results = stream::iter(ports)
        .map(|port| SocketAddr::new(target, port))
        .map(|addr| tokio::spawn(scan_port(addr, timeout_ms)))
        .buffer_unordered(num_threads)
        .filter_map(|res| async { res.unwrap_or(None) })
        .collect()
        .await;

    println!("Scanned {} ports in total.", total_ports);

    results
}

fn print_results(results: &[ScanResult], format: &str) {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(results).unwrap();
            println!("{}", json);
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            for result in results {
                wtr.serialize(result).unwrap();
            }
            wtr.flush().unwrap();
        }
        _ => {
            for result in results {
                println!(
                    "Target: {}, Port: {}, Status: {}, Service: {:?}, Version: {:?}",
                    result.target, result.port, result.status, result.service, result.version
                );
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = command!()
        .name("RPoke")
        .version("1.0")
        .author("hdunl")
        .about("A simple port scanner written in Rust")
        .arg(
            arg!(-t --target <TARGET> "The target IP address to scan")
                .required(true)
        )
        .arg(
            arg!(-s --"start-port" <PORT> "The starting port number (inclusive)")
                .default_value("1")
        )
        .arg(
            arg!(-e --"end-port" <PORT> "The ending port number (inclusive)")
                .default_value("1024")
        )
        .arg(
            arg!(-j --threads <THREADS> "The number of threads to use for scanning")
                .default_value("1000")
        )
        .arg(
            arg!(-T --timeout <TIMEOUT> "The timeout duration in milliseconds")
                .default_value("750")
        )
        .arg(
            arg!(-f --format <FORMAT> "The output format (text, json, csv)")
                .default_value("text")
        )
        .get_matches();

    let target: IpAddr = matches
        .get_one::<String>("target")
        .unwrap()
        .parse()
        .expect("Invalid target IP address");
    let start_port = matches
        .get_one::<String>("start-port")
        .unwrap()
        .parse()
        .expect("Invalid start port");
    let end_port = matches
        .get_one::<String>("end-port")
        .unwrap()
        .parse()
        .expect("Invalid end port");
    let num_threads = matches
        .get_one::<String>("threads")
        .unwrap()
        .parse()
        .expect("Invalid number of threads");
    let timeout_ms = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .expect("Invalid timeout");
    let format = matches.get_one::<String>("format").unwrap();

    let start_time = Instant::now();
    let results = scan_ports(target, start_port, end_port, num_threads, timeout_ms).await;
    let elapsed = start_time.elapsed();
    let total_ports = end_port - start_port + 1;

    print_results(&results, format);
    println!("Scanned {} ports in {:.2} seconds!", total_ports, elapsed.as_secs_f64());
}