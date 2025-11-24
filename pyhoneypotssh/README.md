### SSH honeypot fully customizable. 
```
└─ ⚔ python3 sshpot.py -h                                                                                            [ 6:56PM 2 ⨯ ]
usage: sshpot.py [-h] [-i INTERFACE] [-p PORT] [--hide-attempts] [--no-banner]

SSH Honeypot - Capture SSH authentication attempts

options:
  -h, --help            show this help message and exit
  -i, --interface INTERFACE
                        Interface to bind to (IP address or interface name like tun0, eth0)
  -p, --port PORT       Port to listen on (default: 2222)
  --hide-attempts       Hide username:password in attempts (show only attempt notification)
  --no-banner           Suppress banner display

Examples:
  python3 sshpot.py -i 0.0.0.0 -p 2222
  python3 sshpot.py -i 10.10.14.7 -p 22 --hide-attempts
  python3 sshpot.py -i tun0 -p 2222 (auto-detect tun0 IP)
  python3 sshpot.py --help
```
