# Changelog

## [1.0.0] - 2026-03-23

### Implemented
- TCP SYN scanning (open/closed/filtered) over IPv4 and IPv6
- UDP scanning (open/closed) over IPv4 and IPv6
- packet building
- SIGINT and SIGTERM signal handling

### Known Limitations
- Timeout is not precise 
- IPv6 scanning requires a global IPv6 address on the interface
- IPv6 source address mismatch on interfaces with multiple global IPv6 addresses
- All TCP entries share the same source port which may trigger rate limiting