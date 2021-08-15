import socket
BEACON_PORT = 2770
CLICK_PORT = 25425
BEACON_MESSAGE = "4b4f50000100edd5040045016680"
# BEACON_MESSAGE 4b 4f 50 00 01 00 ed d5 04 00 45 01 66 80"
# Starting Offset    Ending Offset    Length    Content
# 0    17    18    unknown
# 18    21    4    PLC IP
# 22    25    4    Subnet Mask
# 26    29    4    Default IP
# 30    35    6    MAC
# 36    59    24    PLC name
# 60    66    7    unknown
# 67    68    2    Firmware version
# 69    70    2    PLC Status Flags
# 71    72    2    unknown

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
        parse = []
        parse.append(data.hex()[0:17])
        parse.append(data.hex()[17:21])
        parse.append(data.hex()[21:25])
        parse.append(data.hex()[25:29])
        parse.append(data.hex()[29:35])
        parse.append(data[36:59])
        parse.append(data.hex()[59:66])
        parse.append(data.hex()[66:68])
        parse.append(data.hex()[68:70])
        parse.append(data.hex()[70:72])        
        
        print(parse)
    except:
        break
print(responseCount, " responses ... done")

#  Response back
#   
