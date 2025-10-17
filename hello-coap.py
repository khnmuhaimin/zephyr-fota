#!/usr/bin/env python3
# raw_coap_inspect.py
import socket, struct, random

def build_get_request(path="/hello", mid=None):
    ver = 1
    type_ = 0        # Confirmable
    tkl = 0
    first = (ver<<6) | (type_<<4) | tkl
    code = 0x01      # GET
    if mid is None:
        mid = random.randrange(0, 65536)
    header = bytes([first, code]) + struct.pack("!H", mid)

    # encode Uri-Path options (number 11) for each segment
    options = b""
    last = 0
    for seg in path.strip("/").split("/"):
        if not seg:
            continue
        opt_num = 11
        delta = opt_num - last
        val = seg.encode()
        length = len(val)

        def encode_nibble(x):
            if x < 13:
                return x, b""
            if x < 269:
                return 13, bytes([x - 13])
            return 14, struct.pack("!H", x - 269)

        d_nib, d_ext = encode_nibble(delta)
        l_nib, l_ext = encode_nibble(length)
        opt_hdr = bytes([(d_nib << 4) | l_nib])
        options += opt_hdr + d_ext + l_ext + val
        last = opt_num

    return header + options, mid

def parse_coap_packet(data):
    if len(data) < 4:
        raise ValueError("packet too short")
    i = 0
    b0 = data[0]
    ver = (b0 >> 6) & 0x03
    typ = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    code = data[1]
    mid = struct.unpack("!H", data[2:4])[0]
    i = 4
    token = b""
    if tkl:
        token = data[i:i+tkl]; i += tkl

    options = []
    curr_opt = 0
    payload = b""
    while i < len(data):
        if data[i] == 0xFF:
            payload = data[i+1:]
            i = len(data)
            break
        opt_byte = data[i]; i += 1
        delta_nib = (opt_byte >> 4) & 0x0F
        length_nib = opt_byte & 0x0F

        def read_ext(nib):
            nonlocal i
            if nib < 13:
                return nib
            if nib == 13:
                v = data[i]; i += 1; return 13 + v
            if nib == 14:
                v = struct.unpack("!H", data[i:i+2])[0]; i += 2; return 269 + v
            raise ValueError("nibble=15 reserved")

        delta = read_ext(delta_nib)
        length = read_ext(length_nib)
        curr_opt += delta
        val = data[i:i+length]; i += length
        options.append((curr_opt, val))

    return {
        "raw": data,
        "version": ver,
        "type": typ,
        "tkl": tkl,
        "code": code,
        "msg_id": mid,
        "token": token,
        "options": options,
        "payload": payload
    }

def main():
    host = "coap.me"
    port = 5683
    req, mid = build_get_request("/hello")
    print("Request (hex):", req.hex())

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    s.sendto(req, (host, port))
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        print("No response (timeout).")
        return

    pkt = parse_coap_packet(data)
    r = pkt
    raw = r["raw"]
    print()
    print(f"Version | Type | Token_length = {r['version']} | {r['type']} | {r['tkl']}")
    print(f"byte 1 = 0x{raw[0]:02x}  # header (ver={r['version']}, type={r['type']}, tkl={r['tkl']})")
    code_class = r['code'] >> 5
    code_detail = r['code'] & 0x1F
    print(f"byte 2 = 0x{raw[1]:02x}  # Code = {code_class}.{code_detail:02d} (raw {r['code']})")
    print(f"byte 3 = 0x{raw[2]:02x}  # Message ID high")
    print(f"byte 4 = 0x{raw[3]:02x}  # Message ID low  => MID = 0x{r['msg_id']:04x}")
    if r['tkl']:
        print("Token:", r['token'].hex())

    for idx, (num, val) in enumerate(r['options'], 1):
        printable = val.decode('utf-8', errors='replace')
        print(f"Option {idx}: number={num}, length={len(val)}, raw={val.hex()}, ascii='{printable}'")

    print("Payload (hex):", r['payload'].hex())
    print("Payload (ascii):", r['payload'].decode('utf-8', errors='replace'))
    print("Full packet (hex):", raw.hex())

if __name__ == "__main__":
    main()
