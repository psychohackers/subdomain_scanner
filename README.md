# 🔍 Advanced Subdomain Scanner Tool

A powerful and efficient Python tool for discovering subdomains using multiple enumeration techniques with multithreading support.

![Python Version](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🌐 **Multiple Discovery Methods** | DNS resolution, HTTP scanning, and CNAME detection |
| ⚡ **Multithreading Support** | High-performance parallel scanning |
| 🎯 **Smart Wordlist Processing** | Automatic prefix/suffix variations |
| 📊 **Multiple Output Formats** | TXT, JSON, CSV with detailed metadata |
| 📈 **Comprehensive Statistics** | Scan duration, success rates, performance metrics |
| 🔧 **Customizable Scanning** | Adjustable timeouts, threads, and resolvers |
| 🎨 **Colored Output** | Easy-to-read terminal interface with colorama |
| 📝 **Detailed Reporting** | Live subdomains with IPs, status codes, and CNAME records |
| 🔍 **Advanced DNS Resolution** | Multiple DNS resolvers (Google, Cloudflare, Quad9, OpenDNS) |
| 🌊 **HTTP Analysis** | Status codes, content length, and header information |

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)

### Quick Install
```bash
# Clone the repository
git clone https://github.com/psychohackers/subdomain-scanner.git
cd subdomain-scanner

# Install dependencies
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install colorama dnspython requests
```

## 📖 Usage

### Basic Command
```bash
python subdomain.py -d example.com -w wordlist.txt
```

### Advanced Examples
```bash
# High-performance scan with custom threads
python subdomain.py -d example.com -w wordlist.txt -t 100

# HTTP scanning only
python subdomain.py -d example.com -w wordlist.txt --only-http

# Full scan with wordlist variations and JSON output
python subdomain.py -d example.com -w wordlist.txt --http-scan --variations -o results.json --format json

# Custom timeout and output format
python subdomain.py -d example.com -w wordlist.txt --timeout 10 -o results.csv --format csv

# Combined DNS and HTTP scanning
python subdomain.py -d target.com -w subdomains.txt --http-scan -t 50 --timeout 5
```

## 🛠️ Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-d, --domain` | Target domain to scan | **Required** |
| `-w, --wordlist` | Path to subdomain wordlist file | **Required** |
| `-t, --threads` | Number of concurrent threads | `20` |
| `--timeout` | Timeout for DNS/HTTP requests (seconds) | `5` |
| `-o, --output` | Output file to save results | Optional |
| `--format` | Output format: txt, json, csv | `txt` |
| `--http-scan` | Perform HTTP scanning in addition to DNS | `False` |
| `--only-http` | Only perform HTTP scanning (no DNS) | `False` |
| `--variations` | Generate wordlist variations | `False` |
| `-h, --help` | Show help message and exit | |

## 📊 Output Formats

### TXT Format (Default)
```
www.example.com
api.example.com
mail.example.com
```

### JSON Format
```json
[
  {
    "subdomain": "www.example.com",
    "ips": ["93.184.216.34"],
    "cname": "",
    "status_code": 200,
    "content_length": 1256,
    "type": "DNS"
  }
]
```

### CSV Format
```csv
Subdomain,IPs,CNAME,Status Code,Type
www.example.com,93.184.216.34,,,DNS
api.example.com,93.184.216.35,,200,HTTP
```

## 🧪 Wordlist Format

Create a text file with one subdomain per line:

```txt
# subdomains.txt
www
api
mail
admin
test
dev
staging
ftp
cpanel
webmail
```

### Example Wordlist Variations
When using `--variations` flag, the tool automatically generates:
- `www-api`, `api-test`, `dev-admin`, etc.
- `www`, `api-www`, `test-api`, etc.

## 📈 Sample Output

```
[*] Scanning 1500 subdomains on example.com with 50 threads...

[LIVE] www.example.com -> 93.184.216.34
[LIVE] api.example.com -> 93.184.216.35 (CNAME: api.lb.example.com)
[HTTP] admin.example.com -> Status: 200, Size: 4521
[DEAD] test.example.com

==================================================
SCAN STATISTICS
==================================================
Domain: example.com
Total scanned: 1500
Live subdomains: 23
Duration: 45.23 seconds
Threads used: 50
DNS discoveries: 18
HTTP discoveries: 5
==================================================

[+] Results saved to: results.json (JSON)
[+] Scan finished successfully!
```

## 🏗️ Architecture

### Scanning Methods
1. **DNS Resolution**: Uses multiple DNS resolvers for reliable lookups
2. **HTTP Scanning**: Checks HTTP services and gathers response data
3. **CNAME Detection**: Identifies canonical name records
4. **Port Checking**: Optional port scanning for common services

### Multi-threading Model
- Thread pool executor for concurrent scanning
- Configurable thread count for performance tuning
- Graceful error handling in worker threads

## 🔧 Advanced Configuration

### Custom DNS Resolvers
Edit the `dns_resolvers` list in the code to add custom DNS servers:

```python
self.dns_resolvers = [
    '8.8.8.8',           # Google
    '1.1.1.1',           # Cloudflare
    '9.9.9.9',           # Quad9
    '208.67.222.222',    # OpenDNS
    'your.custom.dns'    # Custom resolver
]
```

### Custom HTTP Headers
Modify the `user_agent` and headers in the HTTP scanner for specific requirements.

## ⚠️ Legal & Ethical Usage

### Important Notice
- Only use this tool on domains you own or have explicit permission to test
- Ensure compliance with local laws and regulations
- Respect rate limiting and scanning policies
- The developers are not responsible for misuse

### Responsible Disclosure
- Always follow responsible disclosure practices
- Respect robots.txt and security headers
- Avoid aggressive scanning that may impact services

## 🐛 Troubleshooting

### Common Issues

**DNS Resolution Failures**
```bash
# Increase timeout
python subdomain.py -d example.com -w wordlist.txt --timeout 10

# Use different DNS resolvers (edit code)
```

**Memory Issues with Large Wordlists**
```bash
# Use smaller thread count
python subdomain.py -d example.com -w large_wordlist.txt -t 10
```

**Module Import Errors**
```bash
# Reinstall requirements
pip install --force-reinstall -r requirements.txt
```

### Performance Tips
- Use 50-100 threads for optimal performance
- Adjust timeout based on network conditions
- Use `--variations` for comprehensive coverage
- Combine DNS and HTTP scanning for best results

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

### Development Setup
```bash
git clone https://github.com/yourusername/subdomain-scanner.git
cd subdomain-scanner
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the Python community for excellent networking libraries
- DNS providers for reliable resolution services
- Security researchers for continuous improvement

---

**Happy Scanning!** 🎯

*Remember: With great power comes great responsibility. Always scan ethically and responsibly.*
```

## 📋 requirements.txt

```txt
colorama>=0.4.6
dnspython>=2.4.2
requests>=2.31.0
urllib3>=1.26.0
```

### Installation Command:
```bash
pip install -r requirements.txt
```

This comprehensive README provides:
- Clear installation instructions
- Detailed usage examples
- Complete feature documentation
- Troubleshooting guide
- Ethical usage guidelines
- Performance optimization tips

The tool is now production-ready with professional documentation!
