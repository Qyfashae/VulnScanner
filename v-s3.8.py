import socket
import time
import sys
import requests
from requests import get
import urllib3
import ssl
from datetime import datetime
import threading


ip_address = ""
open_ports = []
banners = []
version = []


def scan_host(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip_address,port))
        if result == 0:
            open_ports.append(port)
            try:
                banner = sock.recv(1024)
                banners.append(banner)
                version.append(banner)
            except:
                pass
            finally:
                sock.close()
    except Exception:
        pass


def check_race_condition(url):
    try:
        response = requests.get(url)

        if response.status_code == 200:
            print("[+] Race Condition Vulnerability Found")
            return True
        else:
            print("[-] Race Condition Vulnerability Not Found")
            return False
    except Exception as e:
        print(e)
        return False


def check_tabnabbing(url):
    try:
        context = ssl.create_default_context()
        response = requests.get(url, verify=False, allow_redirects=True)
        if response.status_code == 200:
            print("[+] Reverse Tabnabbing Vulnerability Found")
            return True
        else:
            print("[-] Reverse Tabnabbing Vulnerability Not Found")
            return False
    except Exception as e:
        print(e)
        return False


def check_xss(url):
    try:
        response = requests.get(url)

        if response.status_code == 200:
            print("[+] XSS Vulnerability Found")
            return True
        else:
            print("[-] XSS Vulnerability Not Found")
            return False
    except Exception as e:
        print(e)
        return False


def get_ip_address():
    global ip_address
    ip_address = socket.gethostbyname(host_name)


def port_scan():
    t1 = datetime.now()
    print("Scanning started at " + str(t1))
    for port in range(1,1025):
        t = threading.Thread(target=scan_host, args=(port,))
        t.start()
    t.join()
    t2 = datetime.now()
    total = t2 - t1
    print("Scanning completed in " + str(total))


def print_results():
    print("IP Address: " + ip_address)
    print("Open Ports: " + str(open_ports))
    print("Banners: " + str(banners))
    print("Version: " + str(version))

if __name__ == '__main__':
    host_name = input("Enter the host to be scanned: ")
    get_ip_address()
    port_scan()
    print_results()

    race_condition_url = "http://" + ip_address + "/race_condition.php"
    tabnabbing_url = "https://" + ip_address + "/tabnabbing.php"
    xss_url = "http://" + ip_address + "/xss.php"

    check_race_condition(race_condition_url)
    check_tabnabbing(tabnabbing_url)
    check_xss(xss_url)
