# Intent:  Blink Red LEDs on Run/Error indicator
# Observations:
#    - This appears to be tied to a specific IP.  It only blinks 192.168.1.32.

import socket
BEACON_PORT = 2770  # This is a "veronica" port - 
CLICK_PORT = 25425
BEACON_MESSAGE = "4b4f50000100d2090e0045016643c0a8012000d07c121589"  # on 192.168.1.32, not all
BEACON_MESSAGE = "4b4f500001004d340e0045016643c0a8011d00d07c19033e"
#  Dissection of BEACON_MESSAGE
#          4b 4f 50 00 01 00    (this part is common with service discovery request)
#        + 4d 34 0e 00 45 01 66 43
#        + IP address (c0a8011d in this case)
#        + MAC address (00:d0:7c:19:03:3e in this case)

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
