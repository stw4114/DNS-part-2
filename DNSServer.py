import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# === CRYPTO ===

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    return f.encrypt(input_string.encode('utf-8'))

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('ascii')  # Fernet expects ascii-safe base64
    decrypted = f.decrypt(encrypted_data)
    return decrypted.decode('utf-8')

# === Setup ===

salt = b'Tandon'
password = 'stw4114@nyu.edu'
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

print(f"Encrypted value: {encrypted_value.decode('ascii')}")
print(f"Decrypted value: {decrypted_value}")

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# === DNS records ===

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('ascii'),),  # store as plain string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

# === DNS server ===

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            print(f"Responding to request: {qname}")

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata_list.append(SOA(dns.rdataclass.IN, dns.rdatatype.SOA,
                                          mname, rname, serial, refresh, retry, expire, minimum))
                else:
                    if isinstance(answer_data, str):
                        if qtype == dns.rdatatype.TXT:
                            rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{answer_data}"')]
                        else:
                            rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        if qtype == dns.rdatatype.TXT:
                            rdata_list = [
                                dns.rdata.from_text(dns.rdataclass.IN, qtype, f'"{data}"')
                                for data in answer_data
                            ]
                        else:
                            rdata_list = [
                                dns.rdata.from_text(dns.rdataclass.IN, qtype, data)
                                for data in answer_data
                            ]

                rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                for rdata in rdata_list:
                    rrset.add(rdata)
                response.answer.append(rrset)

                # Only decrypt and print for TXT:
                if qtype == dns.rdatatype.TXT:
                    try:
                        original_txt = answer_data[0]
                        # If there's accidental quotes, strip:
                        if original_txt.startswith('"') and original_txt.endswith('"'):
                            original_txt = original_txt[1:-1]
                        print(f"Original TXT record: {original_txt!r}")
                        decrypted_txt = decrypt_with_aes(original_txt, password, salt)
                        print(f"Decrypted TXT: {decrypted_txt}")
                    except Exception as e:
                        print(f"decrypt error! Type: {type(e)} Value: {e}")
                        print("Something is wrong with how you are storing the token")

            response.flags |= 1 << 10  # AA flag
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running on 127.0.0.1:53 ...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
