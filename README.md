# SubMap 🗺️

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Version-2.0-red.svg" alt="Version">
</p>

**SubMap** is a fast, comprehensive, and reliable subdomain discovery tool designed for penetration testers, bug bounty hunters, and security researchers. Built with Python's asyncio for maximum performance, SubMap can enumerate subdomains quickly while providing detailed information about each discovery.

```
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██╗   ██╗██████╗ ███╗   ███╗ █████╗ ██████╗          ║
║  ██╔════╝██║   ██║██╔══██╗████╗ ████║██╔══██╗██╔══██╗         ║
║  ███████╗██║   ██║██████╔╝██╔████╔██║███████║██████╔╝         ║
║  ╚════██║██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║██╔═══╝          ║
║  ███████║╚██████╔╝██████╔╝██║ ╚═╝ ██║██║  ██║██║              ║
║  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝              ║
║                                                               ║
║           Advanced Subdomain Discovery Tool v2.0             ║
║              Fast • Comprehensive • Reliable                 ║
╚═══════════════════════════════════════════════════════════════╝
```

## ✨ Features

- 🚀 **Lightning Fast** - Asynchronous DNS resolution with customizable thread count
- 📋 **Built-in Wordlist** - Comprehensive default wordlist with 200+ common subdomains
- 🎯 **Multiple Discovery Methods** - DNS brute force with A and CNAME record support
- 🌐 **HTTP/HTTPS Detection** - Optional web service enumeration with status codes
- 📊 **Multiple Output Formats** - Export results in TXT, JSON, or CSV format
- 🎨 **Beautiful Interface** - Color-coded output with progress tracking
- 🔧 **Highly Configurable** - Extensive customization options
- 🛡️ **Reliable** - Robust error handling and graceful interruption support

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/submap.git
cd submap
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run SubMap:**
```bash
python submap.py -d example.com
```

### Basic Usage

```bash
# Simple subdomain enumeration
python submap.py -d target.com

# Use custom wordlist with 100 threads
python submap.py -d target.com -w custom_wordlist.txt -t 100

# Full enumeration with IP resolution and HTTP checking
python submap.py -d target.com --resolve-ip --check-http -o results.json

# Verbose mode with custom timeout
python submap.py -d target.com -v --timeout 10
```

## 📖 Detailed Usage

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--domain` | `-d` | Target domain (required) | - |
| `--wordlist` | `-w` | Custom wordlist file | Built-in list |
| `--threads` | `-t` | Number of concurrent threads | 50 |
| `--timeout` | - | Request timeout in seconds | 5 |
| `--output` | `-o` | Output file (.txt, .json, .csv) | - |
| `--verbose` | `-v` | Enable verbose output | False |
| `--resolve-ip` | - | Resolve IP addresses | False |
| `--check-http` | - | Check HTTP/HTTPS status | False |
| `--user-agent` | - | Custom User-Agent string | SubMap/2.0 |
| `--proxy` | - | Proxy URL | - |
| `--no-banner` | - | Disable ASCII banner | False |

### Examples

#### 1. Basic Enumeration
```bash
python submap.py -d example.com
```

#### 2. High-Speed Scanning
```bash
python submap.py -d example.com -t 200 --timeout 3
```

#### 3. Comprehensive Analysis
```bash
python submap.py -d example.com \
    --resolve-ip \
    --check-http \
    -o comprehensive_results.json \
    -v
```

#### 4. Custom Wordlist with Stealth Mode
```bash
python submap.py -d example.com \
    -w /path/to/custom_wordlist.txt \
    --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --timeout 8 \
    -t 30
```

#### 5. Export Results in Different Formats
```bash
# JSON format (detailed)
python submap.py -d example.com -o results.json --resolve-ip --check-http

# CSV format (spreadsheet-friendly)
python submap.py -d example.com -o results.csv --resolve-ip

# Text format (simple list)
python submap.py -d example.com -o results.txt
```

## 📋 Default Wordlist

SubMap includes a comprehensive built-in wordlist covering:

- **Common Subdomains**: www, mail, ftp, api, admin, etc.
- **Development**: dev, test, staging, qa, sandbox, etc.
- **Infrastructure**: ns1, ns2, smtp, imap, vpn, etc.
- **Services**: blog, shop, forum, wiki, docs, etc.
- **Cloud & Containers**: aws, k8s, docker, jenkins, etc.
- **Geographic**: us, eu, asia, east, west, etc.
- **Numbered Variations**: www1, api2, db3, etc.

## 📊 Output Formats

### JSON Format
```json
{
  "domain": "example.com",
  "total_found": 15,
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "ips": ["93.184.216.34"],
      "http_info": {
        "https_status": 200,
        "title": "Example Domain",
        "server": "nginx/1.18.0"
      }
    }
  ]
}
```

### CSV Format
```csv
Subdomain,IPs,HTTP_Status,HTTPS_Status,Title,Server
www.example.com,93.184.216.34,,200,Example Domain,nginx/1.18.0
mail.example.com,93.184.216.35,,,Mail Server,postfix
```

### Text Format
```
Subdomain enumeration results for: example.com
Total subdomains found: 15
--------------------------------------------------

www.example.com
  IPs: 93.184.216.34
  HTTPS Status: 200
  Title: Example Domain
  Server: nginx/1.18.0

mail.example.com
  IPs: 93.184.216.35
```

## 🛠️ Advanced Features

### Custom Wordlists

Create your own wordlist file with one subdomain per line:

```
admin
panel
dashboard
api
app
secure
```

Then use it with:
```bash
python submap.py -d target.com -w custom_wordlist.txt
```

### Proxy Support

Use SubMap through a proxy:
```bash
python submap.py -d target.com --proxy http://127.0.0.1:8080
```

### HTTP/HTTPS Analysis

Enable web service detection to gather additional information:
```bash
python submap.py -d target.com --check-http --resolve-ip -v
```

This will show:
- HTTP/HTTPS status codes
- Page titles
- Server headers
- IP addresses

## 🎯 Use Cases

- **Penetration Testing**: Discover attack surface during security assessments
- **Bug Bounty Hunting**: Find hidden subdomains for vulnerability research
- **Asset Discovery**: Enumerate organization's web presence
- **Security Monitoring**: Regular subdomain monitoring for new assets
- **Reconnaissance**: Gather intelligence during OSINT activities

## 🔧 Requirements

- Python 3.7+
- aiohttp
- aiodns

## 📦 Installation Methods

### Method 1: Git Clone
```bash
git clone https://github.com/yourusername/submap.git
cd submap
pip install -r requirements.txt
```

### Method 2: Direct Download
```bash
wget https://raw.githubusercontent.com/yourusername/submap/main/submap.py
pip install aiohttp aiodns
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
git clone https://github.com/yourusername/submap.git
cd submap
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 📝 Changelog

### v2.0 (Current)
- Asynchronous DNS resolution for improved performance
- HTTP/HTTPS status checking
- Multiple output formats (JSON, CSV, TXT)
- Enhanced error handling and progress tracking
- Comprehensive built-in wordlist
- Color-coded terminal output

### v1.0
- Initial release with basic DNS brute forcing
- Custom wordlist support
- Basic output functionality

## 🐛 Troubleshooting

### Common Issues

1. **DNS Resolution Errors**
   - Increase timeout: `--timeout 10`
   - Reduce threads: `-t 25`
   - Check internet connection

2. **Permission Errors**
   - Run with appropriate permissions
   - Check file paths and write permissions

3. **Import Errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Use Python 3.7 or higher

### Performance Tuning

- **High-speed networks**: Increase threads (`-t 100`)
- **Slow networks**: Decrease threads (`-t 20`) and increase timeout (`--timeout 10`)
- **Rate limiting**: Reduce threads and add delays between requests

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/submap/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/submap/discussions)
- **Email**: your.email@domain.com

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the Python asyncio community
- Inspired by various subdomain enumeration tools
- Built with love for the cybersecurity community

## ⭐ Star History

If you find SubMap useful, please consider giving it a star on GitHub!

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>

<p align="center">
  <a href="#submap-️">Back to Top</a>
</p>
