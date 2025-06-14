#!/usr/bin/env python3
"""
SubMap - Advanced Subdomain Discovery Tool
A fast and comprehensive subdomain enumeration tool
"""

import argparse
import asyncio
import aiohttp
import aiodns
import sys
import time
import json
import csv
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import socket
import ssl
from pathlib import Path
import random
from typing import List, Set, Dict, Optional, Tuple
import re

# ASCII Art Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ███╗   ███╗ █████╗ ██████╗          ║
║  ██╔════╝██║   ██║██╔══██╗████╗ ████║██╔══██╗██╔══██╗         ║
║  ███████╗██║   ██║██████╔╝██╔████╔██║███████║██████╔╝         ║
║  ╚════██║██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║██╔═══╝          ║
║  ███████║╚██████╔╝██████╔╝██║ ╚═╝ ██║██║  ██║██║              ║
║  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝              ║
║                                                               ║
║           Advanced Subdomain Discovery Tool v2.0              ║
║              Fast • Comprehensive • Reliable                  ║
╚═══════════════════════════════════════════════════════════════╝
"""

# Default wordlist for subdomain enumeration
DEFAULT_WORDLIST = [
    # Common subdomains
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "www1", "email", "img", "www3",
    "mail3", "mail4", "mail5", "shop", "sql", "secure", "beta", "stage",
    "staging", "api", "web", "cdn", "media", "static", "download", "files",
    
    # Development and testing
    "dev", "development", "test", "testing", "qa", "uat", "demo", "sandbox",
    "temp", "tmp", "staging", "stage", "preview", "pre", "preprod",
    
    # Services and applications
    "api", "app", "application", "service", "services", "mobile", "m",
    "admin", "administrator", "panel", "dashboard", "control", "manage",
    "management", "console", "portal", "gateway", "proxy", "load-balancer",
    
    # Content and media
    "www", "web", "site", "blog", "news", "media", "images", "img", "pics",
    "photos", "videos", "download", "downloads", "files", "docs", "documents",
    "static", "assets", "cdn", "content",
    
    # Infrastructure
    "mail", "email", "smtp", "pop", "pop3", "imap", "webmail", "exchange",
    "mx", "mx1", "mx2", "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "ftp", "sftp", "ssh", "vpn", "firewall", "router", "switch",
    
    # Database and storage
    "db", "database", "mysql", "sql", "postgres", "mongo", "redis", "cache",
    "memcache", "elasticsearch", "es", "kibana", "grafana",
    
    # Monitoring and logging
    "monitor", "monitoring", "logs", "log", "analytics", "stats", "metrics",
    "health", "status", "uptime", "nagios", "zabbix", "prometheus",
    
    # Cloud and containers
    "cloud", "aws", "azure", "gcp", "docker", "k8s", "kubernetes", "swarm",
    "rancher", "openshift", "jenkins", "ci", "cd", "build",
    
    # Security
    "security", "sec", "auth", "authentication", "oauth", "sso", "ldap",
    "ad", "kerberos", "radius", "cert", "certificate", "ssl", "tls",
    
    # Geographic and regional
    "us", "eu", "asia", "ca", "uk", "de", "fr", "jp", "au", "br",
    "east", "west", "north", "south", "central", "region1", "region2",
    
    # Environment specific
    "prod", "production", "live", "www-prod", "api-prod", "staging-api",
    "dev-api", "test-api", "internal", "external", "public", "private",
    
    # Numbered variations
    "www1", "www2", "www3", "api1", "api2", "db1", "db2", "mail1", "mail2",
    "ns1", "ns2", "ns3", "ns4", "web1", "web2", "app1", "app2", "server1",
    "server2", "host1", "host2", "node1", "node2", "cluster1", "cluster2"
]

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SubdomainFinder:
    def __init__(self, domain: str, wordlist: List[str], threads: int = 50, 
                 timeout: int = 5, output_file: str = None, verbose: bool = False,
                 resolve_ip: bool = False, check_http: bool = False, 
                 user_agent: str = None, proxy: str = None):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.resolve_ip = resolve_ip
        self.check_http = check_http
        self.user_agent = user_agent or "SubMap/2.0 (Subdomain Scanner)"
        self.proxy = proxy
        self.found_subdomains: Set[str] = set()
        self.subdomain_info: Dict[str, Dict] = {}
        self.session = None
        self.resolver = None
        
    async def init_session(self):
        """Initialize aiohttp session and DNS resolver"""
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            limit_per_host=self.threads,
            ssl=False,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {'User-Agent': self.user_agent}
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
        
        self.resolver = aiodns.DNSResolver(timeout=self.timeout)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    def print_banner(self):
        """Print the ASCII art banner"""
        print(f"{Colors.CYAN}{BANNER}{Colors.END}")
        print(f"{Colors.YELLOW}Target Domain: {Colors.WHITE}{self.domain}{Colors.END}")
        print(f"{Colors.YELLOW}Wordlist Size: {Colors.WHITE}{len(self.wordlist)}{Colors.END}")
        print(f"{Colors.YELLOW}Threads: {Colors.WHITE}{self.threads}{Colors.END}")
        print(f"{Colors.YELLOW}Timeout: {Colors.WHITE}{self.timeout}s{Colors.END}")
        print("-" * 60)
    
    async def dns_lookup(self, subdomain: str) -> Optional[Tuple[str, List[str]]]:
        """Perform DNS lookup for a subdomain"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Try A record lookup
            result = await self.resolver.query(full_domain, 'A')
            ips = [r.host for r in result]
            return full_domain, ips
        except Exception:
            try:
                # Try CNAME record lookup
                result = await self.resolver.query(full_domain, 'CNAME')
                cnames = [r.cname for r in result]
                return full_domain, cnames
            except Exception:
                return None
    
    async def http_check(self, subdomain: str) -> Optional[Dict]:
        """Check HTTP/HTTPS status of a subdomain"""
        info = {'http_status': None, 'https_status': None, 'title': None, 'server': None}
        
        for scheme in ['https', 'http']:
            url = f"{scheme}://{subdomain}"
            try:
                async with self.session.get(url, allow_redirects=True) as response:
                    info[f'{scheme}_status'] = response.status
                    
                    # Get server header
                    if 'Server' in response.headers:
                        info['server'] = response.headers['Server']
                    
                    # Extract title from HTML
                    if response.content_type and 'html' in response.content_type:
                        try:
                            text = await response.text()
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
                            if title_match:
                                info['title'] = title_match.group(1).strip()
                        except:
                            pass
                    
                    break  # If HTTPS works, don't try HTTP
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}HTTP Error for {url}: {str(e)}{Colors.END}")
                continue
        
        return info if info['http_status'] or info['https_status'] else None
    
    async def check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        """Check if a subdomain exists"""
        async with semaphore:
            # DNS lookup
            dns_result = await self.dns_lookup(subdomain)
            
            if dns_result:
                full_domain, ips = dns_result
                self.found_subdomains.add(full_domain)
                
                # Initialize subdomain info
                self.subdomain_info[full_domain] = {
                    'ips': ips,
                    'http_info': None
                }
                
                # Print immediate result
                ip_str = ', '.join(ips) if self.resolve_ip else ''
                if ip_str:
                    print(f"{Colors.GREEN}[+] {full_domain} -> {ip_str}{Colors.END}")
                else:
                    print(f"{Colors.GREEN}[+] {full_domain}{Colors.END}")
                
                # HTTP check if requested
                if self.check_http:
                    http_info = await self.http_check(full_domain)
                    if http_info:
                        self.subdomain_info[full_domain]['http_info'] = http_info
                        status_str = f"HTTP: {http_info.get('http_status', 'N/A')}, HTTPS: {http_info.get('https_status', 'N/A')}"
                        if self.verbose:
                            print(f"{Colors.BLUE}    └─ {status_str}{Colors.END}")
    
    async def brute_force_dns(self):
        """Perform DNS brute force enumeration"""
        print(f"\n{Colors.CYAN}[*] Starting DNS brute force enumeration...{Colors.END}")
        
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        
        for subdomain in self.wordlist:
            task = asyncio.create_task(self.check_subdomain(subdomain, semaphore))
            tasks.append(task)
        
        # Process tasks with progress indication
        completed = 0
        total = len(tasks)
        
        for task in asyncio.as_completed(tasks):
            await task
            completed += 1
            if completed % 100 == 0 or completed == total:
                progress = (completed / total) * 100
                print(f"\r{Colors.YELLOW}Progress: {completed}/{total} ({progress:.1f}%){Colors.END}", end='', flush=True)
        
        print()  # New line after progress
    
    def save_results(self):
        """Save results to file"""
        if not self.output_file or not self.found_subdomains:
            return
        
        output_path = Path(self.output_file)
        extension = output_path.suffix.lower()
        
        try:
            if extension == '.json':
                self.save_json()
            elif extension == '.csv':
                self.save_csv()
            else:
                self.save_text()
            
            print(f"{Colors.GREEN}[+] Results saved to {self.output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving results: {str(e)}{Colors.END}")
    
    def save_json(self):
        """Save results in JSON format"""
        data = {
            'domain': self.domain,
            'total_found': len(self.found_subdomains),
            'subdomains': []
        }
        
        for subdomain in sorted(self.found_subdomains):
            info = self.subdomain_info.get(subdomain, {})
            subdomain_data = {
                'subdomain': subdomain,
                'ips': info.get('ips', [])
            }
            
            if info.get('http_info'):
                subdomain_data['http_info'] = info['http_info']
            
            data['subdomains'].append(subdomain_data)
        
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def save_csv(self):
        """Save results in CSV format"""
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            headers = ['Subdomain', 'IPs']
            if self.check_http:
                headers.extend(['HTTP_Status', 'HTTPS_Status', 'Title', 'Server'])
            writer.writerow(headers)
            
            # Write data
            for subdomain in sorted(self.found_subdomains):
                info = self.subdomain_info.get(subdomain, {})
                row = [subdomain, '; '.join(info.get('ips', []))]
                
                if self.check_http:
                    http_info = info.get('http_info', {})
                    row.extend([
                        http_info.get('http_status', ''),
                        http_info.get('https_status', ''),
                        http_info.get('title', ''),
                        http_info.get('server', '')
                    ])
                
                writer.writerow(row)
    
    def save_text(self):
        """Save results in plain text format"""
        with open(self.output_file, 'w') as f:
            f.write(f"Subdomain enumeration results for: {self.domain}\n")
            f.write(f"Total subdomains found: {len(self.found_subdomains)}\n")
            f.write("-" * 50 + "\n\n")
            
            for subdomain in sorted(self.found_subdomains):
                info = self.subdomain_info.get(subdomain, {})
                f.write(f"{subdomain}\n")
                
                if info.get('ips'):
                    f.write(f"  IPs: {', '.join(info['ips'])}\n")
                
                if info.get('http_info'):
                    http_info = info['http_info']
                    f.write(f"  HTTP Status: {http_info.get('http_status', 'N/A')}\n")
                    f.write(f"  HTTPS Status: {http_info.get('https_status', 'N/A')}\n")
                    if http_info.get('title'):
                        f.write(f"  Title: {http_info['title']}\n")
                    if http_info.get('server'):
                        f.write(f"  Server: {http_info['server']}\n")
                
                f.write("\n")
    
    def print_summary(self):
        """Print enumeration summary"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}ENUMERATION SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.YELLOW}Domain: {Colors.WHITE}{self.domain}{Colors.END}")
        print(f"{Colors.YELLOW}Total Subdomains Found: {Colors.WHITE}{len(self.found_subdomains)}{Colors.END}")
        print(f"{Colors.YELLOW}Wordlist Size: {Colors.WHITE}{len(self.wordlist)}{Colors.END}")
        
        if self.found_subdomains:
            print(f"\n{Colors.GREEN}Found Subdomains:{Colors.END}")
            for subdomain in sorted(self.found_subdomains):
                info = self.subdomain_info.get(subdomain, {})
                ip_str = f" -> {', '.join(info.get('ips', []))}" if info.get('ips') else ""
                print(f"  {Colors.GREEN}•{Colors.END} {subdomain}{ip_str}")
    
    async def run(self):
        """Main execution method"""
        start_time = time.time()
        
        try:
            await self.init_session()
            await self.brute_force_dns()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Enumeration interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[-] Error during enumeration: {str(e)}{Colors.END}")
        finally:
            await self.close_session()
            
            # Print results
            end_time = time.time()
            elapsed = end_time - start_time
            
            self.print_summary()
            print(f"{Colors.YELLOW}Time Elapsed: {Colors.WHITE}{elapsed:.2f} seconds{Colors.END}")
            
            # Save results
            if self.output_file:
                self.save_results()

def load_wordlist(file_path: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Wordlist file not found: {file_path}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error loading wordlist: {str(e)}{Colors.END}")
        sys.exit(1)

def validate_domain(domain: str) -> str:
    """Validate and clean domain name"""
    # Remove protocol if present
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    
    # Remove path if present
    domain = domain.split('/')[0]
    
    # Remove port if present
    domain = domain.split(':')[0]
    
    # Basic domain validation
    if not domain or '.' not in domain:
        raise ValueError("Invalid domain format")
    
    return domain.lower().strip()

def main():
    parser = argparse.ArgumentParser(
        description="SubMap - Advanced Subdomain Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python submap.py -d example.com
  python submap.py -d example.com -w custom_wordlist.txt -t 100
  python submap.py -d example.com -o results.json --resolve-ip --check-http
  python submap.py -d example.com -t 200 --timeout 10 -v
        """
    )
    
    # Required arguments
    parser.add_argument('-d', '--domain', required=True,
                        help='Target domain to enumerate subdomains for')
    
    # Optional arguments
    parser.add_argument('-w', '--wordlist',
                        help='Path to custom wordlist file (default: built-in wordlist)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of threads to use (default: 50)')
    parser.add_argument('--timeout', type=int, default=5,
                        help='Request timeout in seconds (default: 5)')
    parser.add_argument('-o', '--output',
                        help='Output file (.txt, .json, or .csv)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--resolve-ip', action='store_true',
                        help='Resolve IP addresses for found subdomains')
    parser.add_argument('--check-http', action='store_true',
                        help='Check HTTP/HTTPS status of found subdomains')
    parser.add_argument('--user-agent',
                        help='Custom User-Agent string')
    parser.add_argument('--proxy',
                        help='Proxy URL (http://proxy:port)')
    parser.add_argument('--no-banner', action='store_true',
                        help='Disable ASCII banner')
    
    args = parser.parse_args()
    
    try:
        # Validate domain
        domain = validate_domain(args.domain)
        
        # Load wordlist
        if args.wordlist:
            wordlist = load_wordlist(args.wordlist)
        else:
            wordlist = DEFAULT_WORDLIST.copy()
            # Add some permutations
            additional = []
            for word in DEFAULT_WORDLIST[:20]:  # Take first 20 for permutations
                additional.extend([f"{word}-api", f"{word}-web", f"{word}01", f"{word}02"])
            wordlist.extend(additional)
        
        if not wordlist:
            print(f"{Colors.RED}[-] Empty wordlist{Colors.END}")
            sys.exit(1)
        
        # Create finder instance
        finder = SubdomainFinder(
            domain=domain,
            wordlist=wordlist,
            threads=args.threads,
            timeout=args.timeout,
            output_file=args.output,
            verbose=args.verbose,
            resolve_ip=args.resolve_ip,
            check_http=args.check_http,
            user_agent=args.user_agent,
            proxy=args.proxy
        )
        
        # Print banner
        if not args.no_banner:
            finder.print_banner()
        
        # Run enumeration
        asyncio.run(finder.run())
        
    except ValueError as e:
        print(f"{Colors.RED}[-] {str(e)}{Colors.END}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[-] Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
