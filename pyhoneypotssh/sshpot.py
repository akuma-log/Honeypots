#!/usr/bin/env python3

import paramiko
import socket
import threading
import argparse
import sys
import time
import os
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class SSHServer(paramiko.ServerInterface):
    def __init__(self, show_attempts=True):
        self.show_attempts = show_attempts
        self.attempts = []
        
    def check_auth_password(self, username: str, password: str) -> int:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        attempt = {
            'timestamp': timestamp,
            'username': username,
            'password': password,
            'success': False
        }
        
        # Simulate checking credentials (always fail for honeypot)
        if self.show_attempts:
            print(f"{Colors.YELLOW}[ATTEMPT] {timestamp} - {username}:{password}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[ATTEMPT] {timestamp} - Login attempt from client{Colors.RESET}")
        
        self.attempts.append(attempt)
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.YELLOW}[ATTEMPT] {timestamp} - Public key auth attempt: {username}{Colors.RESET}")
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return "password,publickey"

def get_interface_ip(interface_name):
    """Get the IP address of a network interface"""
    import netifaces
    try:
        addresses = netifaces.ifaddresses(interface_name)
        ipv4 = addresses[netifaces.AF_INET][0]['addr']
        return ipv4
    except Exception as e:
        return None

def handle_connection(client_sock, client_addr, show_attempts):
    transport = None
    try:
        # Set socket timeout to handle bad connections
        client_sock.settimeout(30)
        
        transport = paramiko.Transport(client_sock)
        
        # Load server key
        server_key = paramiko.RSAKey.from_private_key_file('key')
        transport.add_server_key(server_key)
        
        ssh = SSHServer(show_attempts=show_attempts)
        transport.start_server(server=ssh)
        
        # Wait for authentication attempt with timeout
        start_time = time.time()
        while transport.is_active():
            if time.time() - start_time > 30:  # 30 second timeout
                print(f"{Colors.RED}[TIMEOUT] Session timeout for {client_addr[0]}{Colors.RESET}")
                break
                
            # Accept channel with short timeout
            channel = transport.accept(1)
            if channel is not None:
                print(f"{Colors.RED}[FAILED] Authentication completed for {client_addr[0]}{Colors.RESET}")
                channel.close()
                break
                
            time.sleep(0.1)
            
    except paramiko.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
            print(f"{Colors.BLUE}[SCAN] Non-SSH connection or port scan from {client_addr[0]}{Colors.RESET}")
        else:
            print(f"{Colors.RED}[SSH_ERROR] {client_addr[0]}: {str(e)}{Colors.RESET}")
    except socket.timeout:
        print(f"{Colors.BLUE}[TIMEOUT] Socket timeout from {client_addr[0]}{Colors.RESET}")
    except EOFError:
        print(f"{Colors.BLUE}[CLOSED] Connection closed by {client_addr[0]}{Colors.RESET}")
    except Exception as e:
        error_msg = str(e)
        if "Error reading SSH protocol banner" in error_msg:
            print(f"{Colors.BLUE}[SCAN] Non-SSH connection from {client_addr[0]}{Colors.RESET}")
        else:
            print(f"{Colors.RED}[ERROR] Handling {client_addr[0]}: {error_msg}{Colors.RESET}")
    finally:
        try:
            if transport and transport.is_active():
                transport.close()
        except:
            pass
        try:
            client_sock.close()
        except:
            pass

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║           SSH HONEYPOT SERVER                ║
║              by akuma                        ║
║                             x:@gaijinhakka   ║
╚══════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)

def generate_key():
    if not os.path.exists('key'):
        print(f"{Colors.YELLOW}[*] Generating RSA key pair...{Colors.RESET}")
        try:
            from cryptography.hazmat.primitives import serialization as crypto_serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            
            # Generate key using cryptography library
            key = rsa.generate_private_key(
                backend=default_backend(),
                public_exponent=65537,
                key_size=2048
            )
            
            # Save private key
            with open("key", "wb") as f:
                f.write(key.private_bytes(
                    crypto_serialization.Encoding.PEM,
                    crypto_serialization.PrivateFormat.TraditionalOpenSSL,
                    crypto_serialization.NoEncryption()
                ))
            
            print(f"{Colors.GREEN}[+] Key generated successfully!{Colors.RESET}")
        except ImportError:
            # Fallback to ssh-keygen
            os.system('ssh-keygen -t rsa -f key -N "" -q > /dev/null 2>&1')
            print(f"{Colors.GREEN}[+] Key generated successfully!{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[*] Using existing key pair{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='SSH Honeypot - Capture SSH authentication attempts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.CYAN}Examples:{Colors.RESET}
  {Colors.WHITE}python3 sshpot.py -i 0.0.0.0 -p 2222{Colors.RESET}
  {Colors.WHITE}python3 sshpot.py -i 10.10.14.7 -p 22 --hide-attempts{Colors.RESET}
  {Colors.WHITE}python3 sshpot.py -i tun0 -p 2222 (auto-detect tun0 IP){Colors.RESET}
  {Colors.WHITE}python3 sshpot.py --help{Colors.RESET}
        '''
    )
    
    parser.add_argument('-i', '--interface', default='0.0.0.0', 
                       help='Interface to bind to (IP address or interface name like tun0, eth0)')
    parser.add_argument('-p', '--port', type=int, default=2222,
                       help='Port to listen on (default: 2222)')
    parser.add_argument('--hide-attempts', action='store_true',
                       help='Hide username:password in attempts (show only attempt notification)')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress banner display')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # Check if interface is a name (like tun0, eth0) and get its IP
    bind_ip = args.interface
    if not bind_ip.replace('.', '').isdigit():  # If it's not an IP address
        try:
            import netifaces
            detected_ip = get_interface_ip(args.interface)
            if detected_ip:
                print(f"{Colors.GREEN}[*] Detected {args.interface} IP: {detected_ip}{Colors.RESET}")
                bind_ip = detected_ip
            else:
                print(f"{Colors.RED}[ERROR] Could not get IP address for interface {args.interface}{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Available interfaces: {', '.join(netifaces.interfaces())}{Colors.RESET}")
                sys.exit(1)
        except ImportError:
            print(f"{Colors.RED}[ERROR] netifaces module required for interface name detection{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Install: pip install netifaces{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Or use IP address directly: -i 10.10.14.7{Colors.RESET}")
            sys.exit(1)
    
    print(f"{Colors.GREEN}[*] Starting SSH Honeypot...{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Interface: {args.interface} ({bind_ip}){Colors.RESET}")
    print(f"{Colors.BLUE}[*] Port: {args.port}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Show attempts: {not args.hide_attempts}{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Generating/Checking RSA key...{Colors.RESET}")
    
    # Generate key if not exists
    generate_key()
    
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server_sock.bind((bind_ip, args.port))
        server_sock.listen(223)
        
        print(f"\n{Colors.GREEN}[+] Honeypot is running! Waiting for connections...{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Use Ctrl+C to stop the server{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Monitoring connections on {bind_ip}:{args.port}{Colors.RESET}\n")
        
        connection_count = 0
        
        while True:
            client_sock, client_addr = server_sock.accept()
            connection_count += 1
            print(f"{Colors.MAGENTA}[NEW] Connection #{connection_count} from {client_addr[0]}:{client_addr[1]}{Colors.RESET}")
            
            t = threading.Thread(
                target=handle_connection, 
                args=(client_sock, client_addr, not args.hide_attempts),
                daemon=True
            )
            t.start()
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Shutting down honeypot...{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Total connections handled: {connection_count}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.RESET}")
        sys.exit(1)
    finally:
        try:
            server_sock.close()
        except:
            pass

if __name__ == "__main__":
    main()