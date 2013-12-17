#! /bin/sh
socat pipe:contact.json udp-sendto:0.0.0.0:8888

