# RPoke

RPoke is a simple and fast port scanner written in Rust. It allows you to scan a range of ports on a target IP address and provides information about open ports, services, and their versions. This is very much-so still a WIP, more will be added.

## Features

- Scans a specified range of ports on a target IP address
- Supports multiple threads for faster scanning
- Detects common services and their versions
- Provides results in different output formats (text, JSON, CSV)
- Customizable timeout duration for each port scan

## Installation

To use RPoke, you need to have Rust installed on your system. You can install Rust by following the official installation guide: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

Once Rust is installed, you can clone this repository and build the project using Cargo:

```shell
git clone https://github.com/yourusername/rpoke.git
cd rpoke
cargo build --release
```

The compiled binary will be available at `target/release/rpoke`.

## Usage

```
RPoke 1.0
hdunl
A simple port scanner written in Rust

USAGE:
    rpoke [OPTIONS] --target <TARGET>

OPTIONS:
    -e, --end-port <PORT>          The ending port number (inclusive) [default: 1024]
    -f, --format <FORMAT>          The output format (text, json, csv) [default: text]
    -h, --help                     Print help information
    -j, --threads <THREADS>        The number of threads to use for scanning [default: 1000]
    -s, --start-port <PORT>        The starting port number (inclusive) [default: 1]
    -t, --target <TARGET>          The target IP address to scan
    -T, --timeout <TIMEOUT>        The timeout duration in milliseconds [default: 750]
    -V, --version                  Print version information
```

Example usage:

```shell
./rpoke -t 192.168.0.1 -s 1 -e 1000 -j 500 -T 1000 -f json
```

This command scans ports 1 to 1000 on the target IP address 192.168.0.1 using 500 threads and a timeout of 1000 milliseconds. The results will be displayed in JSON format.

## Output Formats

RPoke supports three output formats:

- `text` (default): Displays the results in a human-readable text format.
- `json`: Outputs the results in JSON format.
- `csv`: Outputs the results in CSV format.


## Acknowledgements

RPoke was inspired by various port scanning tools and tutorials. Special thanks to the Rust community for their excellent libraries and resources.
