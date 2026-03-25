import socket
import threading
import base64
import sys
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

DH_PARAMS_PEM = b'''
-----BEGIN DH PARAMETERS-----
MIIBiAKCAYEA7slflbrJJEa2bjMMN+ubBBKqfEtmyHx/qMv5d3NzZL+4YKXz8lOZ
kGXulkC1Fx//TatUI8MXA0K67CiS15vt6nwcIPc1whSZs1uywdrCcioMo3v2BmFE
dOhQ1Y2U1YTgp2fwCZTJ5Tp4ViN1Oagpg8AmJxCwJO7ODE9UqY1Fg5YKnWG/XSZM
l6ZifQSWAWEXT/f63RDpktjCnSHKKSh39U5MTHbh/SLCHMxgjl6+QNyjoTjSHw6N
czuDKSRk/xRWFvtHn3Vr599APGqA3xwpdOBNhCmRSe63jTdfPb5C0KzPcJw1is2y
kD5CamuO+YRPJkuAiv1AOH2tWe6e5R6bxakY4BiU/aO63F3RXxw1s6CppczD8SOc
KJLUnYedNtBqIpKh6hZPrHGzpzA4uxQo25ZXO/XL8XtVMKozQSu1UtJ2wpD97Vxz
i1xUChTj4ycL/ZgtlJqJxcYJ2gM0HMuAfNb/onatb6t9s1xRKV2eXhN8mhgQNARC
YGvDw9In76F3AgEC
-----END DH PARAMETERS-----
'''

# Load DH parameters once globally
try:
    DH_PARAMS = serialization.load_pem_parameters(DH_PARAMS_PEM)
except Exception as e:
    print(f"Error loading DH parameters: {e}")
    sys.exit(1)

class P2PChat:
    """P2P encrypted chat using Diffie-Hellman key exchange"""
    
    BUFFER_SIZE = 8192
    DEFAULT_PORT = 5005
    EXIT_COMMANDS = {'exit', 'quit', 'q'}
    
    def __init__(self):
        self.socket: Optional[socket.socket] = None
        self.cipher: Optional[Fernet] = None
        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
    
    def _generate_keypair(self) -> Tuple[dh.DHPrivateKey, bytes]:
        """Generate DH keypair and return private key with public key bytes"""
        private_key = DH_PARAMS.generate_private_key()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_bytes
    
    def _derive_shared_secret(self, private_key: dh.DHPrivateKey, 
                             peer_public_bytes: bytes) -> bytes:
        """Derive shared secret using peer's public key"""
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p_chat_handshake_v1',
        ).derive(shared_secret)
    
    def _create_cipher(self, shared_secret: bytes) -> Fernet:
        """Create Fernet cipher from shared secret"""
        key = base64.urlsafe_b64encode(shared_secret)
        return Fernet(key)
    
    def _setup_host(self, port: int) -> Optional[socket.socket]:
        """Setup host mode - wait for incoming connection"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(1)
            print(f"📡 Hosting on port {port}. Waiting for connection...")
            
            conn, addr = server_socket.accept()
            print(f"✅ Connected to: {addr[0]}:{addr[1]}")
            server_socket.close()
            return conn
        except Exception as e:
            print(f"❌ Host error: {e}")
            return None
    
    def _setup_client(self, host: str, port: int) -> Optional[socket.socket]:
        """Setup client mode - connect to host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            print(f"✅ Connected to {host}:{port}")
            return sock
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return None
    
    def _perform_key_exchange(self, sock: socket.socket, is_host: bool) -> bool:
        """Perform Diffie-Hellman key exchange"""
        try:
            private_key, my_public_bytes = self._generate_keypair()
            
            if is_host:
                # Host sends first
                sock.send(my_public_bytes)
                peer_public_bytes = sock.recv(self.BUFFER_SIZE)
            else:
                # Client receives first
                peer_public_bytes = sock.recv(self.BUFFER_SIZE)
                sock.send(my_public_bytes)
            
            if not peer_public_bytes:
                print("❌ Key exchange failed: no data received")
                return False
            
            shared_secret = self._derive_shared_secret(private_key, peer_public_bytes)
            self.cipher = self._create_cipher(shared_secret)
            print("🔐 Secure channel established!")
            return True
            
        except Exception as e:
            print(f"❌ Key exchange error: {e}")
            return False
    
    def _receive_messages(self, sock: socket.socket):
        """Background thread for receiving messages"""
        while self.running:
            try:
                encrypted_data = sock.recv(self.BUFFER_SIZE)
                if not encrypted_data:
                    break
                
                decrypted_msg = self.cipher.decrypt(encrypted_data).decode()
                print(f"\r\033[K[👤] {decrypted_msg}\n💬 You: ", end="", flush=True)
                
            except socket.timeout:
                continue
            except Exception:
                break
        
        print("\n🔌 Connection closed by peer")
        self.running = False
    
    def _send_message(self, sock: socket.socket, message: str) -> bool:
        """Encrypt and send a message"""
        try:
            encrypted_msg = self.cipher.encrypt(message.encode())
            sock.send(encrypted_msg)
            return True
        except Exception as e:
            print(f"❌ Send error: {e}")
            return False
    
    def run(self):
        """Main chat session"""
        print("=" * 50)
        print("🔒 P2P Encrypted Chat - Diffie-Hellman Key Exchange")
        print("=" * 50)
        
        # Mode selection
        mode = input("Select mode: (1) Host [Wait] or (2) Client [Connect]: ").strip()
        if mode not in ('1', '2'):
            print("❌ Invalid selection")
            return
        
        # Port configuration
        port_input = input(f"Enter port (default {self.DEFAULT_PORT}): ").strip()
        port = int(port_input) if port_input else self.DEFAULT_PORT
        
        # Establish connection
        sock = None
        if mode == '1':
            sock = self._setup_host(port)
        else:
            host = input("Enter host IP (e.g., 127.0.0.1): ").strip()
            if not host:
                print("❌ Host IP required")
                return
            sock = self._setup_client(host, port)
        
        if not sock:
            return
        
        # Perform key exchange
        is_host = (mode == '1')
        if not self._perform_key_exchange(sock, is_host):
            sock.close()
            return
        
        # Start chat
        self.running = True
        self.socket = sock
        sock.settimeout(1.0)  # 1 second timeout for receive thread
        
        # Start receive thread
        self.receive_thread = threading.Thread(target=self._receive_messages, args=(sock,), daemon=True)
        self.receive_thread.start()
        
        print("\n" + "=" * 50)
        print("💬 Chat active! Commands:")
        print("  • Type your message and press Enter")
        print("  • Type 'exit', 'quit', or 'q' to leave")
        print("=" * 50 + "\n")
        
        # Main message loop
        try:
            while self.running:
                message = input("💬 You: ").strip()
                
                if not message:
                    continue
                
                if message.lower() in self.EXIT_COMMANDS:
                    print("👋 Disconnecting...")
                    break
                
                if not self._send_message(sock, message):
                    break
                    
        except KeyboardInterrupt:
            print("\n👋 Interrupted by user")
        finally:
            self.running = False
            sock.close()
            print("🔌 Disconnected")

def main():
    """Entry point with error handling"""
    try:
        chat = P2PChat()
        chat.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())