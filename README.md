# IPK project 1 - L4 Scanner

## Overview

Simple network L4 scanner that works both for UDP and TCP protocol on IPV4 and IPV6 addresses. 
Program uses raw sockets for TCP (program builds own SYN packets) and DGRAM sockets for UDP 
to send probes on defined IP address / hostname while using threads per single address - one  is 
used for sending and checking timeout of each entry/probe, while the other is listening for replies 
using libpcap library.


## Build

Program can be compiled by running command `make` inside the root of the repository.
```bash
make
```

To remove everything created by `make` run `make clean`.
```bash
make clean
```

## Usage
>**PROGRAM MUST BE RUN USING ADMINISTRATOR PRIVILEGES DUE TO RAW SOCKETS**
```bash
./ipk-L4-scan -i INTERFACE [-t PORTS] [-u PORTS] HOST [-w TIMEOUT]
```
**Mandatory arguments** are `INTERFACE`, `HOST` and atleast one `PORT`

### Arguments
| Argument | Description | Required |
|----------|-------------|----------|
| `-i INTERFACE` | Source interface which will be used | Yes |
| `HOST` | Target hostname or IPV4/V6 addres | Yes |
| `-t PORTS` | TCP ports to scan | * |
| `-u PORTS` | UDP ports to scan  | * |
| `-w TIMEOUT` | Timeout in miliseconds for resending probes | No |
| `-h`, `--help` | Print usage | No |

\*Atleast one of PORT is required.

Each argument may be used at most 1 time due to implementation. All arguments may be used in any order. 
Ports must be in ranges 1-665535 and can be defined as (1-500 or 1,25,2 or 5 ) no cominations such as 1,25-20,5 are allowed.

### Examples

```bash
#print all avaibale interfaces
./ipk-L4-scan -i
```
```bash
#scan 2 localhost UDP ports
sudo ./ipk-L4-scan -i eth0 -u 53,67 localhost
```
```bash
#scan address for UDP and TCP ports
sudo ./ipk-L4-scan -i eth0 -u 80,440  192.168.0.1 -t 80,443
```
```bash
#send help message
./ipk-L4-scan --help
```
### Output format

Program outputs one or more lines each containing: `IP PORT PROTOCOL STATE`.

Example:
```bash
sudo ./ipk-L4-scan -i lo -t 80,443 localhost
```
```
127.0.0.1 80 tcp closed
127.0.0.1 443 tcp closed
```

## Implemented Features

### TCP scanning
Sending SYN packets to addresses through RAW sockets, based on the response port state is decided as such:
- RST packet -> port is ***closed***,
- SYN + ACK packet - > port is ***open***,
- No response `once` until timeout -> send TCP packet again,
- No response `twice` until timeout -> port is ***filtered***.

Tcp scanning creates own TCP header and if address is IPV4 also the IP header and does correct checksums.

### UDP scanning
Sending UDP messages to addresses through DGRAM sockets based on the response port state is decided as such:
- ICMP(type 3 code 3) response -> port is ***closed***,
- ICMPv6(type 4 code 1) response -> port is ***closed***,
- No response until timeout -> port is ***open***.

### Hostname
Program supports IPV4, IPV6 and also hostname as targets.
Hostname names are resolve using 'getaddrainfoo' into corresponding ip addresses for scanning.

### Signal handling
Program supports termination with `SIGINT` or `SIGTERM`, upon termination all allocated memory is freed and program exists with success.

### Errors and printing
Upon any error program prints error message to `stderr` and exits with a corresponding non-zero exit code.

| Exit Code | Name | Description |
|-----------|------|-------------|
| 0 | `ERR_SUCCESS` | Program completed successfully |
| 1 | `ERR_FAILURE` | General failure |
| 2 | `ERR_INVALID_ARGUMENT` | Invalid or missing argument |
| 3 | `ERR_GETIFADDRS` | Failed to resolve source interfaces |
| 4 | `ERR_HOSTNAME` | Failed to resolve target hostname |
| 5 | `ERR_SOCKET` | Everything related to socket(creation, binding, sending messages) |
| 6 | `ERR_NO_INTERFACE` | No interface not found or missing IPV4/IPV6 address |
| 7 | `ERR_PCAP` | Any libpcap error |
| 8 | `ERR_MUTEX` | Thread mutex initialization failed |
| 9 | `ERR_CLOCK` | Failed to resolve current time |
| 99 | `ERR_MALLOC` | Memory allocation failed |

### Program flow and design choices
1. **Parse arguments** - resolve all arguments and input them into `Scanner` struct for easy manipulation, using bitmaps to save memory.
2. **Resolve hostname** - get target ipaddress/-es by using `getaddrinfo`.
3. **Resolve interface** - get all interfaces and store one ipv4 and one global ipv6 into `Scanner` struct for easy manipulation.
4. **Init sockets** - create at most *4* socket for each send type(TCP-IPV4, TCP-IPV6, UDP-IPV4, UDP-ipv6), bind them or set options and store them into `Sockets` struct due to creating new socket fd being time demanding operation,
5. **Create `IPScan` struct** - which holds all data needed for scanning a single address:
    target/source addresses, socket file descriptors, pcap handler, mutex, and an array,
    of `ScanEntry` structs (one per port) tracking state and timeout of each entry.
6. **Scan addresses** - for each address:
    - reset `IPscan` struct(filter, target address, sockets),
    - create two threads - one for receiving(Send) and one for listening to responses(receive):
        - Send thread operates similar to FSM. Over each entry it decides what to do based on their state(either to send or set that its completed),while also tracking timeout time for each entry, also breaks Receive `pcap_loop` upon checking that all entries are completed
        - Receive thread runs `pcap_loop` which handles returning packets and setting corresponding States based on the response.
7. **cleanup** - after scanning all allocated memory is freed and program exits with success error code.

## Testing


## *Known* Limitations

- **Timeout precision** — timeout is checked inside a loop that iterates over all entries. 
  For large port ranges, by the time a specific entry is checked, more time may have passed than the set timeout, 
  causing a port to be marked different state that it would have even if a response arrived just after the threshold.

- **IPv6 requires global address** — the interface must have a global IPv6 address.
  Interfaces with only link-local addresses cannot be used for IPv6 scanning.

- **IPv6 source address mismatch** — when an interface has multiple global IPv6 addresses, 
the address the kernel uses for sending may differ from the one the program selected, causing responses to not be recognized.

- **Rate limiting** — all TCP entries share the same source port, which may trigger
  rate limiting or firewall rules on some targets.

## References

- [RFC 793 - Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [TCP/IPv4/IPv6 checksum implementation](https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/)
- [Sending raw Ethernet packets in C](https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/)
- [C signal handling](https://en.wikipedia.org/wiki/C_signal_handling)
- [pcap documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [getaddrinfo man page](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html)
- [pthread documentation](https://man7.org/linux/man-pages/man7/pthreads.7.html)
- [getifaddrs man page](https://man7.org/linux/man-pages/man3/getifaddrs.3.html)
- [errno man page](https://man7.org/linux/man-pages/man3/errno.3.html)