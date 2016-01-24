sniffy
======

Python3 network packet sniffer

Description
===========

sniffy is a network packet sniffer that outputs the parsed headers in JSON to standard output.

It currently parses the following:

  - Ethernet
  - IPv4
  - ICMP
  - UDP
  - TCP
  - DNS

Requirements
============

  - dnspython3

Usage
=====

```bash
sniffy.py -i <interface_name>
```
