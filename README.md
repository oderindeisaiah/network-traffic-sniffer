# Network Traffic Sniffer & Protocol Analyzer

A low-level, high-performance passive network sniffing engine written entirely in native Python. This tool binds directly to a raw network interface to capture, unpack, and log live inbound and outbound packet streams without relying on external third-party traffic libraries.

---

## Technical Architecture

The architecture functions entirely within the client-side execution loop, binding to low-level operating system network abstractions:

* **Layer 2 (Data Link):** Extracts MAC routing headers from raw incoming frames to map interface bindings.
* **Layer 3 (Network):** Decodes IPv4 packets, exposing TTL (Time to Live), packet lengths, and logical routing endpoints.
* **Layer 4 (Transport):** Unpacks TCP structures (including control flag mapping for SYN, ACK, FIN, and RST fields) and UDP datagram payloads via precise binary slicing.

