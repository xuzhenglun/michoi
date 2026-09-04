import socket, struct, sys, time
# Minimal PENGUIN0 Pad: answer the door emulator, unlock, send one voice packet.
PORT=10077
def penguin(family, opcode, declared, body):
    h=b"PENGUIN0"+struct.pack("<H",family)+struct.pack("<I",opcode)+struct.pack("<I",declared)+b"\x00"*14
    return h+body
def endpoints():
    def station(sid, ip):
        b=sid.encode()[:20]; b=b+b"\x00"*(20-len(b)); return b+socket.inet_aton(ip)
    return station("M00000000000","192.168.124.2")+station("S00000000000","192.168.124.61")
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1",PORT)); s.settimeout(10)
print("fake pad listening", PORT, flush=True)
peer=None; got_setup=False
try:
    data,peer=s.recvfrom(4096)
    got_setup = data[:8]==b"PENGUIN0"
    print("received first datagram from door", peer, "is_penguin", got_setup, "opcode", data[10:14].hex(), flush=True)
except socket.timeout:
    print("no ring received", flush=True); sys.exit(1)
# answer (00b7/05), unlock (00b7/06), one audio packet (00b7/0a type 3)
env=endpoints()
s.sendto(penguin(0x00b7,0x05,80,env), peer)
time.sleep(0.1)
s.sendto(penguin(0x00b7,0x06,80,env), peer)
time.sleep(0.1)
media_hdr=struct.pack("<HHHHH",3,0,1,1,512)  # type=audio,seq,frag_count,idx,valid
s.sendto(penguin(0x00b7,0x0a,602,env+media_hdr+b"\x00"*512), peer)
print("sent answer + unlock + 1 voice packet", flush=True)
time.sleep(1.0)
