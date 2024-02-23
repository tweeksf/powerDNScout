"""
Author: Dave Mitchell
Date: 2024-02-12
Description: Gathers DNS query data from open PowerDNS resolvers. 

This script gathers DNS query and client information data from open PowerDNS resolvers discovered by Shodan.
"""

import argparse
import json
import requests
import socks 
import socket
from cymruwhois import Client
from datetime import datetime
from bs4 import BeautifulSoup
from shodan import Shodan
import concurrent.futures

# Read config.json for Shodan API key and SOCKS5 proxy settings
def read_config():
    print("-- PowerDNScout --")
    print("Reading config.json...")
    with open('config.json') as json_file:
        data = json.load(json_file)
    print("Config loaded.")
    return data['SHODAN_API_KEY'], data.get('use_socks', False), data.get('socks_proxy', None)

# Shodan search for PowerDNS Authoritative Server Monitor
def shodan_search(api_key):
    print("Performing Shodan search...")
    api = Shodan(api_key)
    page = 1
    ip_dict = {}
    while True:
        results = api.search('PowerDNS Authoritative Server Monitor', page=page)
        for result in results['matches']:
            ip_dict[result['ip_str']] = {'country': result['location']['country_name'], 'org': result['org']}
        
        if len(results['matches']) < 100:
            break
        page += 1
    print("Shodan search complete.")
    return ip_dict

# Fetch WHOIS information for discovered DNS client IPs
def fetch_whois(remote_ip):
    try:
        c = Client()
        r = c.lookup(remote_ip)
        return remote_ip, {'AS': r.asn, 'IP': r.prefix, 'AS Name': r.owner}
    except Exception as e:
        print(f"Could not get WHOIS for {remote_ip}: {e}")
        return remote_ip, {}

# Fetch DNS queries and client IPs from open PowerDNS resolvers
def fetch_dns_queries(ip_dict, use_socks, socks_proxy):
    print("Fetching DNS queries and clients...")
    
    for ip, info in ip_dict.items():
        for path in ['unauth-queries', 'remotes']:
            url = f'http://{ip}:8081/?ring={path}'
            print(f"\nFetching {url}")
            
            try:
                if use_socks and socks_proxy:
                    print(f"Using SOCKS5 proxy: {socks_proxy['host']}:{socks_proxy['port']}")
                    socks.set_default_proxy(socks.SOCKS5, socks_proxy['host'], socks_proxy['port'])
                    socket.socket = socks.socksocket
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print("Great success.")
                    soup = BeautifulSoup(response.text, 'html.parser')
                    table = soup.find_all('table')[0]
                    rows = table.find_all('tr')
                    data = {}
                    for row in rows[1:]:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            key = cols[0].text.strip()
                            if key == "Total:" or key == "Rest:":
                                continue
                            try:
                                value = int(cols[1].text.strip())
                            except ValueError:
                                continue
                            if '/' in key:
                                domain, query_type, *_ = key.split('/')
                                if domain not in data:
                                    data[domain] = {'count': 0, 'query_type': []}
                                data[domain]['query_type'].append(query_type)
                                data[domain]['count'] += value
                            else:
                                data[key] = value
                    if path == 'unauth-queries':
                        info['dns_queries'] = data
                    else:  # path == 'remotes'
                        info['remotes'] = data
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future_to_ip = {executor.submit(fetch_whois, remote_ip): remote_ip for remote_ip in data.keys()}
                            for future in concurrent.futures.as_completed(future_to_ip):
                                remote_ip = future_to_ip[future]
                                try:
                                    whois_info = future.result()[1]
                                    if 'IP' in whois_info:
                                        del whois_info['IP']
                                    if remote_ip in info['remotes']:
                                        info['remotes'][remote_ip] = {
                                            'count': info['remotes'][remote_ip],
                                            'whois': whois_info
                                        }
                                except Exception as e:
                                    print(f"Error occurred during WHOIS lookup for {remote_ip}: {e}")
                else:
                    print(f"Failed with status code: {response.status_code}")
            except (requests.exceptions.Timeout, requests.exceptions.ConnectTimeout):
                print("Request timed out.")
                continue
            except requests.exceptions.ConnectionError:
                print("Connection to server went derp.")
                continue
    
    print("\nCompleted.")
    return ip_dict

# Print summary of DNS queries and clients
def print_summary(ip_dict, filename, json_format):
    common_remote_ips = {}
    with open(filename, 'w') as f:
        if json_format:
            json.dump(ip_dict, f, indent=4)
        else:
            f.write("Summary:\n")
            for ip, info in ip_dict.items():
                f.write(f"\nIP: {ip}\n")
                f.write(f"Country: {info['country']} \nOrg: {info['org']}\n\n")
                f.write("DNS queries:\n")
                for query, data in info.get('dns_queries', {}).items():
                    f.write(f"{query}, Count: {data['count']}, Query Type: {', '.join(data['query_type'])}\n")
                f.write("\nRemote clients:\n")
                for remote_ip, data in info.get('remotes', {}).items():
                    f.write(f"{remote_ip:<15}: {data.get('whois', {}).get('AS Name', 'N/A')}\n")
                    if remote_ip in common_remote_ips:
                        common_remote_ips[remote_ip].append(ip)
                    else:
                        common_remote_ips[remote_ip] = [ip]
            f.write("\nCommon DNS clients:\n")
            for remote_ip, ips in common_remote_ips.items():
                if len(ips) > 1:
                    f.write(f"{remote_ip:<15} seen in resolvers: {', '.join(ips)}\n")

# Main
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    date_str = datetime.now().strftime('%Y%m%d')

    if args.json:
        filename = f'logs/open_powerdns_resolvers_{date_str}.json'
    else:
        filename = f'logs/open_powerdns_resolvers_{date_str}.txt'

    api_key, use_socks, socks_proxy = read_config()
    ip_dict = shodan_search(api_key)
    ip_dict = fetch_dns_queries(ip_dict, use_socks, socks_proxy)
    print_summary(ip_dict, filename, args.json)

if __name__ == "__main__":
    main()