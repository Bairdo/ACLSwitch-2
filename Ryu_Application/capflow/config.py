# Mac address of authentication server
AUTH_SERVER_MAC = "b8:ae:ed:7a:05:3b"
# IP address of authentication server
AUTH_SERVER_IP = "192.168.1.42"
# Switch port authentication server is facing
AUTH_SERVER_PORT = 3



#CTL_REST_IP = "192.168.1.39"
CTL_REST_IP = "10.0.1.8"
CTL_REST_PORT = "8080"
CTL_MAC = "b8:27:eb:b0:1d:6b"

GATEWAY_MAC = "24:09:95:79:31:7e"
GATEWAY_PORT = 1
# L2 src-dst pairs which are whitelisted and does not need to go through auth
WHITELIST = [
    (AUTH_SERVER_MAC, CTL_MAC),
    (CTL_MAC, AUTH_SERVER_MAC),
    (GATEWAY_MAC, "00:1d:a2:80:60:64"),
    ("00:1d:a2:80:60:64", GATEWAY_MAC)
#    (GATEWAY_MAC, "9c:eb:e8:01:6e:db"),
#    ("9c:eb:e8:01:6e:db", GATEWAY_MAC)
]
