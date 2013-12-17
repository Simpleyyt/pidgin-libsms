#! /bin/sh
socat pipe:msg.json udp-sendto:0.0.0.0:8888

