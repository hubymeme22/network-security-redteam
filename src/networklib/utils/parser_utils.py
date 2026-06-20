from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP
from networklib.utils.constants import HTTP_COMMANDS, FTP_COMMANDS, SMTP_COMMANDS

import datetime


def parse_http_request(raw_request: str) -> dict:
    """
    Parses http requests sent
    """
    if '\r\n\r\n' in raw_request:
        header_part, body = raw_request.split('\r\n\r\n', 1)
    else:
        # fallback if there is no body
        header_part = raw_request
        body = ""

    lines = header_part.split('\r\n')
    request_line = lines[0]
    request_line_parts = request_line.split(' ')

    if len(request_line_parts) < 3:
        return {"error": "Malformed request line"}

    method = request_line_parts[0]
    path = request_line_parts[1]
    version = request_line_parts[2]

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    return {
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
        "body": body
    }


def unencrypted_packet_capture(packet: Packet) -> dict:
    """
    A simple function for parsing unencrypted contents
    going into and out the network.

    This is specifically designed to log the detected raw
    unencrypted communications in the network. Currently the following
    are the network protocols that are being detected:

    - http
    - ftp
    - telnet
    - smtp

    Note: to use this function, the packet must have a TCP layer
    as well as Raw layer with valid load content
    """
    # decode usable variables in the top most level which can be used throughout below
    raw_packet = packet[Raw].load.decode('utf-8', errors='ignore')
    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)

    meta_template = {
        "time": str(datetime.datetime.now()),
        "ip_address": ip_layer.src,
        "ip_to": ip_layer.dst
    }

    # detection for possible ftp protocol
    # reference: https://medium.com/@vasiqmz/analyzing-ftp-traffic-cfd1b18bf30a
    if any(command in raw_packet for command in FTP_COMMANDS) or (tcp_layer.dport == 21):
        meta_template.update({
            "packet_summary": {
                "type": "ftp",
                "data": raw_packet,
            }
        })

        return meta_template

    # detection for possible SMTP protocol
    # reference: https://www.stevenrombauts.be/2018/12/test-smtp-with-telnet-or-openssl/
    if any(command in raw_packet for command in SMTP_COMMANDS) or (tcp_layer.dport == 25):
        meta_template.update({
            "packet_summary": {
                "type": "ftp",
                "data": raw_packet,
            }
        })

        return meta_template

    # detection for HTTP protocol
    # reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview
    if any(method in raw_packet for method in HTTP_COMMANDS) or (tcp_layer.dport == 80):
        parsed_http_content = parse_http_request(raw_packet)
        meta_template.update({
            "packet_summary": {
                "type": "http",
                "data": parsed_http_content
            }
        })

        return meta_template

    return None
