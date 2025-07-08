import socket
import threading
import dns.message
import dns.flags
import dns.rrset
import dns.rdatatype
import dns.rdataclass

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import base64

# -------------------------------
# Encryption Helpers
# -------------------------------

def generate_aes_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32)
    return key

def encrypt_with_aes(data, password, salt):
    key = generate_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_with_aes(enc_data, password, salt):
    enc = base64.b64decode(enc_data)
    iv = enc[:16]
    ct = enc[16:]
    key = generate_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# -------------------------------
# Prepare encryption parameters
# -------------------------------

salt = b'Tandon'
password = "your_netid@nyu.edu"   # <<<< REPLACE with your NYU email
secret_data = "AlwaysWatching"

encrypted_data = encrypt_with_aes(secret_data, password, salt)

# -------------------------------
# DNS Records Dictionary
# -------------------------------

records = {
    'example.com.': {'A': '1.2.3.4'},

    'safebank.com.': {'A': '192.168.1.102'},
    'google.com.': {'A': '192.168.1.103'},
    'legitsite.com.': {'A': '192.168.1.104'},
    'yahoo.com.': {'A': '192.168.1.105'},
    'nyu.edu.': {
        'A': '192.168.1.106',
        'TXT': encrypted_data,
        'MX': (10, 'mxa-00256a01.gslb.pphosted.com.'),
        'AAAA': '2001:db8:85a3::8a2e:373:7312',
        'NS': 'ns1.nyu.edu.'
    }
}

# -------------------------------
# DNS Server Logic
# -------------------------------

def handle_client(sock):
    while True:
        try:
            data, addr = sock.recvfrom(512)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = dns.rdatatype.to_text(question.rdtype)

            print(f"Received query for: {qname} type: {qtype}")

            if qname in records and qtype in records[qname]:
                rrset = None
                if qtype == 'A':
                    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.A, records[qname]['A'])
                elif qtype == 'TXT':
                    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{records[qname]["TXT"]}"')
                elif qtype == 'MX':
                    priority, exchange = records[qname]['MX']
                    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.MX, f"{priority} {exchange}")
                elif qtype == 'AAAA':
                    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.AAAA, records[qname]['AAAA'])
                elif qtype == 'NS':
                    rrset = dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.NS, records[qname]['NS'])

                if rrset:
                    response.answer.append(rrset)
                    response.flags |= dns.flags.AA  # Authoritative answer flag
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)

            sock.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print("\nShutting down server.")
            break
        except Exception as e:
            print(f"Error handling request: {e}")

# -------------------------------
# Run the Server
# -------------------------------

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))  # Bind to all interfaces on port 53
    print("DNS server running on UDP port 53... (Press Ctrl+C to stop)")

    server_thread = threading.Thread(target=handle_client, args=(sock,))
    server_thread.start()

    try:
        while True:
            cmd = input()
            if cmd.strip().lower() == 'q':
                print("Shutting down.")
                break
    except KeyboardInterrupt:
        print("Exiting...")

if __name__ == "__main__":
    main()
