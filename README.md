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

  - [pcappy](https://github.com/allfro/pcappy)
  - dnspython3

Usage
=====

(as root)
```bash
sniffy.py -i <interface_name>
```
