# network-security-redteam

A collection of foundational network security and red teaming tools built from the ground up. This repository serves as a practical, hands-on compilation of network mechanics, protocol manipulation, and security concepts explored through raw code.

---

## 🚫 No-AI Manifesto (EXCEPT README - because I'm bad with words!!)

Every line of logic, packet structure, and implementation in this repository was written **entirely by human hands** (my hands ofc). 

While AI tools are excellent for automation, true mastery of network security requires wrestling with sockets, byte order, and protocol quirks manually. To ensure deep comprehension, **no LLMs or AI assistants were used to generate the core code or logic** in this project. It is 100% organic, hand-crafted code.

---

## 🛠️ Included Projects

| Project Name | Description | Key Protocols / Modules |
| :--- | :--- | :--- |
| **ARP Spoofer** | Man-in-the-Middle utility to redirect localized traffic via cache poisoning. | Scapy, ARP, Layer 2 Routing |
| **DNS Traffic Sniffing** | A simple dns sniffing tool that can be used in network to monitor site requests | Scapy, DNS |


### 🔮 P.S. Future Proofing & Modularization
Looking ahead, my goal is to refactor these scripts into a highly customizable, unified framework. In the near future, I plan to abstract the core packet-crafting logic into a reusable, custom module. This will allow anyone to easily import these network utilities and build bespoke security tooling on top of them without rewriting the boilerplate.

## 🗺️ Project Roadmap & Checklist

This checklist tracks my progress as I build out the repository. It moves from basic Layer 2/3 manipulation up to application-layer utilities.

- [X] **ARP Spoofer** - Basic Man-in-the-Middle utility via cache poisoning.
- [X] **DNS Sniffer** - Intercepting DNS requests on a local network and display site queries.
- [X] **Network Scanner** - Method for scanning network through ARP broadcasting, this can also be used for checking vulnerability of the network.
- [X] **Packet Sniffer & Credentials Extractor** - A tool to parse raw network traffic and extract sensitive unencrypted data (HTTP, FTP, etc.).
- [ ] **Custom C2 (Command & Control) Beacon** - A primitive reverse-shell framework utilizing custom encoding/encryption over TCP/UDP.
- [ ] **Different SSL Stripping methods** - Will cover a lot of experimental (my research) [sslstriping](https://www.cyberark.com/what-is/ssl-stripping-attacks/) methods starting from basic [sslstrip](https://www.cyberark.com/what-is/ssl-stripping-attacks/) methods to advanced chained methods to perform complex credential harvesting methods

PS. As much as possible, I want to avoid DoS attack methods just because

I will also work on different IDS mechanisms on `blue-team` repository (will be out soon) for detecting these attacks, as well as application of Machine Learning on defending networks :>
