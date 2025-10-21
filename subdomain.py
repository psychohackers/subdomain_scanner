#!/usr/bin/env python3
"""
Advanced Subdomain Scanner Tool
A powerful subdomain enumeration tool with multiple discovery techniques.
"""

import socket
import concurrent.futures
import argparse
import sys
import time
import random
import json
import os
from urllib.parse import urlparse
import requests
import dns.resolver
from datetime import datetime

# Try to import colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        GREEN = RED = CYAN = YELLOW = BLUE = MAGENTA = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = ""
    COLORS_ENABLED = False
    print("[!] colorama not installed. Install with: pip install colorama")

def print_banner():
    """Display the tool banner"""
    banner = f"""
{Fore.CYAN}
   ____        _     _                         _____                                      
  / ___| _   _| |__ | | ___  ___ ___  ___     / ____|_ __  _   _ _ __ ___  _ __ ___   ___ 
  \___ \| | | | '_ \| |/ _ \/ __/ __|/ _ \   | |   | '_ \| | | | '__/ _ \| '_ ` _ \ / _ \\
   ___) | |_| | |_) | |  __/\__ \__ \ (_) |  | |___| | | | |_| | | | (_) | | | | | |  __/
  |____/ \__,_|_.__/|_|\___||___/___/\___/    \____|_| |_|\__,_|_|  \___/|_| |_| |_|\___|

{Fore.GREEN}                    ⚡ Advanced Subdomain Scanner Tool - Python 3 ⚡
{Fore.YELLOW}                            Coded by: [Mr psycho]
                            GitHub: [@mr-psycho]
                            Instagram: [@the_psycho_of_hackers]
    """
    print(banner)

class SubdomainScanner:
    def __init__(self, domain, threads=20, timeout=5, user_agent=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.found_subdomains = []
        self.stats = {
            'scanned': 0,
            'found': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Common DNS resolvers
        self.dns_resolvers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222', # OpenDNS
            '8.8.4.4'       # Google Secondary
        ]

    def scan_subdomain_dns(self, subdomain):
        """
        Scan a single subdomain using DNS resolution.
        
        Args:
            subdomain (str): The subdomain prefix to check
            
        Returns:
            dict or None: Subdomain info if live, None if dead
        """
        url = f"{subdomain}.{self.domain}"
        self.stats['scanned'] += 1
        
        try:
            # Try multiple DNS resolvers
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [random.choice(self.dns_resolvers)]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            answers = resolver.resolve(url, 'A')
            ips = [str(answer) for answer in answers]
            
            # Get additional info
            cname = self.get_cname(url)
            status = "LIVE"
            
            result = {
                'subdomain': url,
                'ips': ips,
                'cname': cname,
                'status': status,
                'type': 'DNS'
            }
            
            print(f"{Fore.GREEN}[LIVE] {url} -> {', '.join(ips)} {f'(CNAME: {cname})' if cname else ''}")
            return result
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            print(f"{Fore.RED}[DEAD] {url}")
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}[ERROR] {url} -> {str(e)}")
            return None

    def scan_subdomain_http(self, subdomain):
        """
        Scan a single subdomain using HTTP requests.
        
        Args:
            subdomain (str): The subdomain prefix to check
            
        Returns:
            dict or None: Subdomain info if live, None if dead
        """
        url = f"http://{subdomain}.{self.domain}"
        self.stats['scanned'] += 1
        
        try:
            response = requests.get(
                url, 
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent},
                allow_redirects=True,
                verify=False
            )
            
            result = {
                'subdomain': url.replace('http://', ''),
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'status': 'LIVE',
                'type': 'HTTP'
            }
            
            print(f"{Fore.BLUE}[HTTP] {url} -> Status: {response.status_code}, Size: {len(response.content)}")
            return result
            
        except requests.RequestException:
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}[ERROR] {url} -> {str(e)}")
            return None

    def get_cname(self, subdomain):
        """Get CNAME record for subdomain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(subdomain, 'CNAME')
            return str(answers[0].target)
        except:
            return None

    def check_common_ports(self, ip, ports=[80, 443, 8080, 8443]):
        """Check common ports on found IP"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                pass
        return open_ports

    def generate_wordlist_variations(self, base_wordlist):
        """Generate variations of base wordlist"""
        variations = set(base_wordlist)
        
        # Add common prefixes/suffixes
        prefixes = ['', 'www', 'api', 'test', 'dev', 'staging', 'prod', 'admin']
        suffixes = ['', '-api', '-test', '-dev', '-admin', '-old', '-new']
        
        for word in base_wordlist:
            for prefix in prefixes:
                for suffix in suffixes:
                    if prefix and suffix:
                        variations.add(f"{prefix}-{word}{suffix}")
                    elif prefix:
                        variations.add(f"{prefix}-{word}")
                    elif suffix:
                        variations.add(f"{word}{suffix}")
        
        return list(variations)

def load_wordlist(wordlist_path):
    """
    Load subdomain wordlist from file.
    
    Args:
        wordlist_path (str): Path to the wordlist file
        
    Returns:
        list: List of subdomain names
    """
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            wordlist = [line.strip() for line in file if line.strip()]
            print(f"{Fore.CYAN}[+] Loaded {len(wordlist)} words from {wordlist_path}")
            return wordlist
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to read wordlist: {e}")
        sys.exit(1)

def save_results(output_file, results, format='txt'):
    """
    Save results to file in various formats.
    
    Args:
        output_file (str): Path to the output file
        results (list): List of results to save
        format (str): Output format (txt, json, csv)
    """
    try:
        if format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'IPs', 'CNAME', 'Status Code', 'Type'])
                for result in results:
                    writer.writerow([
                        result.get('subdomain', ''),
                        ','.join(result.get('ips', [])),
                        result.get('cname', ''),
                        result.get('status_code', ''),
                        result.get('type', '')
                    ])
        else:  # txt
            with open(output_file, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"{result.get('subdomain', '')}\n")
        
        print(f"{Fore.CYAN}[+] Results saved to: {output_file} ({format.upper()})")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to write output file: {e}")

def print_statistics(scanner, results):
    """Print scanning statistics"""
    duration = scanner.stats['end_time'] - scanner.stats['start_time']
    
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.GREEN}SCAN STATISTICS")
    print(f"{Fore.CYAN}{'='*50}")
    print(f"{Fore.WHITE}Domain: {scanner.domain}")
    print(f"{Fore.WHITE}Total scanned: {scanner.stats['scanned']}")
    print(f"{Fore.WHITE}Live subdomains: {len(results)}")
    print(f"{Fore.WHITE}Duration: {duration:.2f} seconds")
    print(f"{Fore.WHITE}Threads used: {scanner.threads}")
    
    # Group by type
    dns_results = [r for r in results if r.get('type') == 'DNS']
    http_results = [r for r in results if r.get('type') == 'HTTP']
    
    print(f"{Fore.WHITE}DNS discoveries: {len(dns_results)}")
    print(f"{Fore.WHITE}HTTP discoveries: {len(http_results)}")
    print(f"{Fore.CYAN}{'='*50}")

def main():
    """Main function to run the subdomain scanner"""
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Scanner - Discover subdomains using multiple techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain.py -d example.com -w wordlist.txt
  python subdomain.py -d example.com -w wordlist.txt -t 50 --timeout 10
  python subdomain.py -d example.com -w wordlist.txt -o results.json --format json
  python subdomain.py -d example.com -w wordlist.txt --http-scan --variations
        """
    )
    
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for DNS/HTTP requests (default: 5)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--format", choices=['txt', 'json', 'csv'], default='txt', help="Output format (default: txt)")
    parser.add_argument("--http-scan", action="store_true", help="Perform HTTP scanning in addition to DNS")
    parser.add_argument("--variations", action="store_true", help="Generate wordlist variations")
    parser.add_argument("--only-http", action="store_true", help="Only perform HTTP scanning (no DNS)")
    
    args = parser.parse_args()

    # Initialize scanner
    scanner = SubdomainScanner(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout
    )

    # Load and process wordlist
    base_wordlist = load_wordlist(args.wordlist)
    
    if args.variations:
        wordlist = scanner.generate_wordlist_variations(base_wordlist)
        print(f"{Fore.CYAN}[+] Generated {len(wordlist)} word variations")
    else:
        wordlist = base_wordlist

    scanner.stats['start_time'] = time.time()
    all_results = []

    print(f"{Fore.CYAN}[*] Scanning {len(wordlist)} subdomains on {args.domain} with {args.threads} threads...\n")

    # DNS Scanning
    if not args.only_http:
        print(f"{Fore.YELLOW}[*] Starting DNS scan...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_subdomain = {
                executor.submit(scanner.scan_subdomain_dns, sub): sub 
                for sub in wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    all_results.append(result)
                    scanner.stats['found'] += 1

    # HTTP Scanning
    if args.http_scan or args.only_http:
        print(f"{Fore.YELLOW}[*] Starting HTTP scan...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_subdomain = {
                executor.submit(scanner.scan_subdomain_http, sub): sub 
                for sub in wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    # Check if subdomain already found via DNS
                    existing = any(r.get('subdomain') == result.get('subdomain') for r in all_results)
                    if not existing:
                        all_results.append(result)
                        scanner.stats['found'] += 1

    scanner.stats['end_time'] = time.time()

    # Display results
    if all_results:
        print(f"\n{Fore.GREEN}[+] Scan complete. {len(all_results)} live subdomains found:")
        for result in all_results:
            subdomain = result.get('subdomain', '')
            ips = result.get('ips', [])
            status_code = result.get('status_code', '')
            
            if ips:
                print(f"{Fore.GREEN} - {subdomain} -> {', '.join(ips)}")
            elif status_code:
                print(f"{Fore.BLUE} - {subdomain} -> HTTP {status_code}")
            else:
                print(f"{Fore.GREEN} - {subdomain}")

    else:
        print(f"\n{Fore.RED}[-] No live subdomains found.")

    # Print statistics
    print_statistics(scanner, all_results)

    # Save results
    if args.output:
        save_results(args.output, all_results, args.format)

    print(f"\n{Fore.CYAN}[+] Scan finished successfully!")

if __name__ == "__main__":
    print_banner()
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

