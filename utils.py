import socket
import time
import requests
import pdb
import ipaddress

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

def is_valid_ip(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False
    
def resolve_ip(domain):
    try:
        response = requests.get(f"https://dns.google/resolve?name={domain}", headers=headers)
        ip = response.json()["Answer"][0]["data"]
        return ip
    except (requests.exceptions.RequestException, KeyError):
        return None
    
def get_ip_location(ip):
    try:
        url = f"https://api.ip.sb/geoip/{ip}" 
        
        resp = requests.get(url, headers=headers,timeout=1)
        if resp.status_code != 200:
            return ""
        data = resp.json()
        country = data["country_code"]
        return country
    except:
        return "US"

# ip = "64.176.58.15"  
# country = get_ip_location(ip)
# print(f"{ip} is located in {country}")

def test_latency(ip, port):
    try:
        socket.setdefaulttimeout(1)  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start = time.time()
        result = sock.connect_ex((ip, port))
        end = time.time()
        sock.close()
        return end - start
    except:
        return 10000

def ping_port(ip_address, port):
    try:
        # 创建套接字对象
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 设置超时时间（单位：秒）
        timeout = 1
        
        # 尝试建立连接并计算延迟
        start_time = time.time()
        sock.settimeout(timeout)
        sock.connect((ip_address, port))
        end_time = time.time()
        
        latency = end_time - start_time
        return latency
            
    except socket.error as e:
        return 10000
    finally:
        # 关闭套接字
        sock.close()

# 用法示例
# print(test_latency('64.176.58.15', 46154))  # 测试IP地址和端口的延迟
# import base64
# import json
# stt ={
#   "v": "2",
#   "ps": "vmess节点示例",
#   "add": "46.29.166.237",
#   "port": "47555",
#   "id": "0c49cd19-2758-4d38-e6a8-11f2d6635860",
#   "aid": "0",
#   "net": "none",
#   "type": "none",
#   "host": "",
#   "path": "",
#   "tls": "none"
# }
# cc = base64.b64encode(json.dumps(stt).encode()).decode()
# print(f"vmess://{cc}")
# pdb.set_trace()
