import socket
BEACON_PORT = 2770
CLICK_PORT = 25425
BEACON_MESSAGE = "4b4f50000100edd5040045016680"
# BEACON_MESSAGE 4b 4f 50 00 01 00 ed d5 04 00 45 01 66 80"

beacon = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
beacon.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
beacon.bind(("", BEACON_PORT))

message = bytes.fromhex(BEACON_MESSAGE)
print("sending beacon ...")
print(f'\tport:\t {CLICK_PORT}')
print(f'\tdata:\t', message.hex())
print()
beacon.sendto(message, ('<broadcast>', CLICK_PORT))

print("data received ...")
responseCount = 0
beacon.settimeout(5.0)
while True:
    try:
        data, addr = beacon.recvfrom(1024)
        responseCount += 1
        print(f'Response {responseCount}:')
        print(f'--received meta information (IP, port): {addr}')
        # print("--client received data: %s" % data.hex())
        print(f'--client received data (hex):', data.hex())
        print(f'--client received data (raw): {data}')
        print()
    except:
        break
print(responseCount, " responses ... done")

#  Response back
#   
