import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
except Exception: pass
s.bind(("0.0.0.0",10008)); s.settimeout(8)
print("fake pad discovery listening 10008", flush=True)
try:
    while True:
        d,peer=s.recvfrom(1024)
        if d[:1]==b"\x01":
            end=d.index(b"\x00",1) if b"\x00" in d[1:] else len(d)
            room=d[1:end].decode(errors="replace")
            print("query for", room, "from", peer, flush=True)
            reply=b"\x02"+room.encode()+b"\x00"*(34-len(room))
            s.sendto(reply, peer)
            print("replied", flush=True)
            break
except socket.timeout:
    print("timeout", flush=True)
