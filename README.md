# Network Sniffer

This is a simple network sniffer written in Python that utilizes raw sockets to sniff ICMP packets and detect hosts on a specified subnet.

## Getting Started

These instructions will help you set up and run the network scanner on your local machine.

### Prerequisites

- Python 3.x

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/il3241ya/Sniffer.git
    ```

2. Change into the project directory:

    ```bash
    cd Sniffer
    ```

## Usage

Run the network sniffer using the following command:

```bash
python scanner.py [host_ip]
```

### Command Line Options

- `host_ip` Specify the host IP address to bind the socket

## Features

- Sends UDP messages to all hosts in a specified subnet.
- Sniffs incoming ICMP packets to detect live hosts.
