"""Minimal loopback SSTP interoperability peer using only synthetic credentials."""

import argparse
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import queue
import socket
import ssl
import struct
import subprocess
import tempfile
import threading

USER = b"fixture"
PASSWORD = bytes([102, 105, 120, 116, 117, 114, 101, 32, 34, 39, 92, 33])
CLIENT_IP = ipaddress.IPv4Address("192.0.2.2").packed
PEER_IP = ipaddress.IPv4Address("192.0.2.1").packed
NONCE = bytes(range(32))
CHALLENGE = bytes(range(16))
LCP, IPCP, PAP, CHAP = (0xC021, 0x8021, 0xC023, 0xC223)
METHODS = {"pap": b"\xc0\x23", "chap": b"\xc2\x23\x05", "mschapv2": b"\xc2\x23\x81"}
REFUSALS = {"pap": "refuse-pap", "chap": "refuse-chap", "mschapv2": "refuse-mschap-v2"}
OPENSSL = os.environ.get("SSTP_TEST_OPENSSL", "openssl")


def openssl(*args, data=None):
    return subprocess.run([OPENSSL, *args], input=data, capture_output=True, check=True).stdout


def create_certificates(folder):
    openssl("req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
            "-subj", "/CN=Fixture Root", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign", "-keyout", str(folder / "root.key"),
            "-out", str(folder / "root.pem"))
    openssl("req", "-new", "-nodes", "-newkey", "rsa:2048", "-subj", "/CN=Fixture Leaf",
            "-keyout", str(folder / "leaf.key"), "-out", str(folder / "leaf.csr"))
    (folder / "leaf.conf").write_text(
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,DNS:*.fixture.test\n")
    openssl("x509", "-req", "-in", str(folder / "leaf.csr"), "-CA", str(folder / "root.pem"),
            "-CAkey", str(folder / "root.key"), "-set_serial", "1", "-days", "1",
            "-extfile", str(folder / "leaf.conf"), "-out", str(folder / "leaf.pem"))


def sha1(*values):
    return hashlib.sha1(b"".join(values)).digest()


def md4(data):
    return openssl("dgst", "-md4", "-provider", "legacy", "-binary", data=data)


def des_encrypt(seven_bytes, data):
    bits = int.from_bytes(seven_bytes, "big")
    key = bytes((bits >> (49 - 7 * index) & 0x7F) << 1 for index in range(8))
    return openssl("enc", "-des-ecb", "-provider", "legacy", "-K", key.hex(), "-nopad", data=data)


def mschapv2_response(peer_challenge, password):
    challenge = sha1(peer_challenge, CHALLENGE, USER)[:8]
    nt_hash = md4(password.decode().encode("utf-16-le"))
    padded = nt_hash + bytes(5)
    nt_response = b"".join(des_encrypt(padded[i:i+7], challenge) for i in (0, 7, 14))
    hash_hash = md4(nt_hash)
    response_digest = sha1(hash_hash, nt_response, b"Magic server to client signing constant")
    success = sha1(response_digest, challenge, b"Pad to make it do more than one iteration")
    master = sha1(hash_hash, nt_response, b"This is the MPPE Master Key")[:16]
    client_keys = b"".join(
        sha1(master, bytes(40), b"On the client side, this is the " + client +
             b" key; on the server side, it is the " + server + b" key.", b"\xf2" * 40)[:16]
        for client, server in ((b"send", b"receive"), (b"receive", b"send"))
    )
    return nt_response, b"S=" + success.hex().upper().encode(), client_keys


def packet(payload, control=False):
    return struct.pack("!BBH", 0x10, int(control), 4 + len(payload)) + payload


def control(message, attribute=None):
    if attribute is None:
        return packet(struct.pack("!HH", message, 0), True)
    kind, value = attribute
    return packet(struct.pack("!HHBBH", message, 1, 0, kind, 4 + len(value)) + value, True)


def ppp(protocol, code, identifier, payload=b""):
    return b"\xff\x03" + struct.pack("!HBBH", protocol, code, identifier, 4 + len(payload)) + payload


def read_packet(reader):
    header = reader.read(4)
    if not header:
        raise EOFError("client closed SSTP stream")
    version, flags, length = struct.unpack("!BBH", header)
    assert version == 0x10 and 4 <= length <= 4095
    payload = reader.read(length - 4)
    assert len(payload) == length - 4
    return bool(flags & 1), payload


def read_ppp(payload):
    if payload.startswith(b"\xff\x03"):
        payload = payload[2:]
    if len(payload) < 6 or payload[0] & 1:
        return None
    protocol, code, identifier, size = struct.unpack("!HBBH", payload[:6])
    return protocol, code, identifier, payload[6:size+2]


def ppp_options(data):
    while data:
        assert len(data) >= 2 and 2 <= data[1] <= len(data)
        length = data[1]
        yield data[:length]
        data = data[length:]


def verify_binding(payload, keys, cert):
    assert len(payload) == 108
    assert payload[4:12] == b"\x00\x03\x00\x68\x00\x00\x00\x02"
    assert payload[12:44] == NONCE
    assert payload[44:76] == hashlib.sha256(cert).digest()
    key = hmac.digest(keys, b"SSTP inner method derived CMK\x20\x00\x01", "sha256")
    assert hmac.compare_digest(payload[76:], hmac.digest(key, packet(payload[:76] + bytes(32), True), "sha256"))


def serve(tls, method, cert, accept_password):
    reader = tls.makefile("rb")
    first = reader.readline()
    assert first.startswith(b"SSTP_DUPLEX_POST "), first
    for _ in range(32):
        header = reader.readline(4096)
        if header == b"\r\n":
            break
        assert header
    else:
        raise AssertionError("incomplete SSTP HTTP request")
    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
    is_control, payload = read_packet(reader)
    assert is_control and int.from_bytes(payload[:2], "big") == 1
    tls.sendall(control(2, (4, b"\0\0\0\2" + NONCE)))
    auth_option = bytes([3, 2 + len(METHODS[method])]) + METHODS[method]
    client_lcp = peer_lcp = auth_started = authenticated = bound = client_ipcp = peer_ipcp = False
    keys = bytes(32)
    tls.sendall(packet(ppp(LCP, 1, 101, auth_option)))
    while not (bound and client_ipcp and peer_ipcp):
        is_control, payload = read_packet(reader)
        if is_control:
            message = int.from_bytes(payload[:2], "big")
            if message == 4:
                assert authenticated
                verify_binding(payload, keys, cert)
                bound = True
            elif message == 8:
                tls.sendall(control(9))
            else:
                raise AssertionError(f"unexpected SSTP message {message}")
            continue
        contents = read_ppp(payload)
        if contents is None:
            continue
        protocol, code, identifier, data = contents
        if protocol == LCP:
            if code == 1:
                tls.sendall(packet(ppp(LCP, 2, identifier, data)))
                client_lcp = True
            elif code == 2 and identifier == 101:
                assert data == auth_option
                peer_lcp = True
            elif code in (3, 4) and identifier == 101:
                raise AssertionError(f"client declined {method}")
            if client_lcp and peer_lcp and not auth_started:
                auth_started = True
                if method != "pap":
                    tls.sendall(packet(ppp(CHAP, 1, 102, bytes([len(CHALLENGE)]) + CHALLENGE + b"peer")))
        elif protocol in (PAP, CHAP):
            assert auth_started
            if method == "pap":
                assert protocol == PAP and code == 1
                length = data[0]
                assert data[1:1+length] == USER
                assert data[2+length:] == (PASSWORD if accept_password else b"wrong")
                payload = ppp(PAP, 2 if accept_password else 3, identifier, b"\0")
            elif method == "chap":
                assert protocol == CHAP and code == 2 and data[0] == 16
                assert data[1:17] == hashlib.md5(bytes([identifier]) + (PASSWORD if accept_password else b"wrong") + CHALLENGE).digest()
                assert data[17:] == USER
                payload = ppp(CHAP, 3 if accept_password else 4, identifier)
            else:
                assert protocol == CHAP and code == 2 and data[0] == 49 and data[50:] == USER
                response, success, keys = mschapv2_response(data[1:17], PASSWORD if accept_password else b"wrong")
                assert data[25:49] == response
                payload = ppp(CHAP, 3 if accept_password else 4, identifier, success if accept_password else b"E=691 R=0")
            tls.sendall(packet(payload))
            if not accept_password:
                return "auth rejected"
            authenticated = True
            tls.sendall(packet(ppp(IPCP, 1, 103, b"\x03\x06" + PEER_IP)))
        elif protocol == IPCP:
            assert authenticated
            if code == 1:
                expected = b"\x03\x06" + CLIENT_IP
                rejected = b"".join(option for option in ppp_options(data) if option[:2] != b"\x03\x06")
                if rejected:
                    tls.sendall(packet(ppp(IPCP, 4, identifier, rejected)))
                elif data != expected:
                    tls.sendall(packet(ppp(IPCP, 3, identifier, expected)))
                else:
                    tls.sendall(packet(ppp(IPCP, 2, identifier, data)))
                    client_ipcp = True
            elif code == 2 and identifier == 103:
                peer_ipcp = data == b"\x03\x06" + PEER_IP
        elif protocol == 0x80FD or protocol == 0x8057:  # CCP and IPv6CP
            tls.sendall(packet(ppp(LCP, 8, 104, struct.pack("!H", protocol) + payload[4:])))
    return "TLS, PPP authentication, Crypto Binding and IPCP passed"


def run_case(engine, folder, context, cert, method=None, ca=True, hostname="localhost", correct=True):
    outcome = queue.Queue()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(10)

        def server():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(8)
                    with context.wrap_socket(connection, server_side=True) as tls:
                        if method is None:
                            delivered = tls.recv(4096)
                            outcome.put(delivered.startswith(b"SSTP_DUPLEX_POST"))
                        else:
                            outcome.put(serve(tls, method, cert, correct))
            except (ssl.SSLError, ConnectionResetError) as error:
                outcome.put(False if method is None else error)
            except Exception as error:
                outcome.put(error)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        command = [
            str(engine), "--user", USER.decode(), "--host", hostname,
            "--priv-dir", str(folder / "jail"), "--log-level", "3", "--log-stderr", "--tls-ext",
        ]
        if method is None:
            command.append("--nolaunchpppd")
        if ca:
            command += ["--ca-cert", str(folder / "root.pem")]
        command += [f"127.0.0.1:{listener.getsockname()[1]}"]
        if method is not None:
            command += ["noauth", "nodefaultroute", "nodetach", "logfd", "2", "nomppe", "noipv6",
                        "novj", "noipdefault", "ipcp-accept-local",
                        "refuse-eap", "refuse-mschap", *[flag for auth, flag in REFUSALS.items() if auth != method]]
        environment = {**os.environ, "SSTP_OPTIONS_DIR": str(folder), "SSTP_PASSWORD_STDIN": "1"}
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment, cwd=folder) as client:
            client.stdin.write((PASSWORD if correct else b"wrong") + b"\n")
            client.stdin.close()
            client.stdin = None
            try:
                result = outcome.get(timeout=20)
            except queue.Empty:
                result = TimeoutError(f"{method or hostname} did not finish")
            finally:
                if client.poll() is None:
                    client.terminate()
                try:
                    stdout, stderr = client.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    client.kill()
                    stdout, stderr = client.communicate()
        thread.join(1)
        log = (stdout + stderr).decode(errors="replace").replace("\0", "")
        assert PASSWORD.decode() not in log
        if isinstance(result, Exception):
            raise AssertionError(log) from result
        print(f"{method or hostname}: {result}")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", type=lambda arg: Path(arg).resolve())
    parser.add_argument("--ppp", action="store_true", help="exercise password methods with a PPP peer")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sstp-loopback-") as name:
        folder = Path(name)
        (folder / "jail").mkdir()
        create_certificates(folder)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(folder / "leaf.pem", folder / "leaf.key")
        cert = ssl.PEM_cert_to_DER_cert((folder / "leaf.pem").read_text())
        assert run_case(args.engine, folder, context, cert, ca=False) is False
        assert run_case(args.engine, folder, context, cert, hostname="other.test") is False
        assert run_case(args.engine, folder, context, cert, hostname="vpn.fixture.test") is True
        assert run_case(args.engine, folder, context, cert) is True
        if args.ppp:
            for method in METHODS:
                assert "IPCP passed" in run_case(args.engine, folder, context, cert, method=method)
                assert run_case(args.engine, folder, context, cert, method=method, correct=False) == "auth rejected"


if __name__ == "__main__":
    main()
