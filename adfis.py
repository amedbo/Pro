#!/usr/bin/env python3
"""
ADFIS v4.0 - Advanced Digital Forensic and Intelligence System
Complete cyber intelligence platform with vulnerability scanning, network analysis,
and threat assessment capabilities.
"""

import os
import sys
import json
import time
import signal
import asyncio
import aiohttp
import socket
import ssl
import nmap
import dns.resolver
import dns.zone
import dns.query
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import lru_cache
from hashlib import sha256
from urllib.parse import urlparse
import ipaddress
import whois
import subprocess
import logging
import logging.handlers
import warnings
import tempfile
import platform

# Suppress warnings
warnings.filterwarnings("ignore")

# Constants
VERSION = "4.0"
DEFAULT_USER_AGENT = f"ADFIS/{VERSION} (Advanced Cyber Intelligence Platform)"
MAX_CONCURRENT_TASKS = 50

# Configure advanced logging
class CustomFormatter(logging.Formatter):
    """Custom log formatter with colors"""
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logger = logging.getLogger('ADFIS')
logger.setLevel(logging.INFO)

# Console handler with colors
ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())

# File handler with rotation
fh = logging.handlers.RotatingFileHandler(
    'adfis_operations.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logger.addHandler(ch)
logger.addHandler(fh)

# Enums
class ScanIntensity(Enum):
    LIGHT = 1
    STANDARD = 2
    AGGRESSIVE = 3
    PENETRATION = 4

class ThreatLevel(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# Data Classes
@dataclass
class Vulnerability:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    exploit_available: bool
    remediation: str

@dataclass
class Service:
    port: int
    protocol: str
    name: str
    version: str
    banner: str
    vulnerabilities: List[Vulnerability]

@dataclass
class Host:
    ip: str
    hostname: str
    os: str
    os_accuracy: float
    services: List[Service]
    tls_fingerprints: Dict[str, str]
    last_seen: datetime

class NVDLoader:
    """National Vulnerability Database loader"""
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, session: aiohttp.ClientSession):
        self.api_key = os.getenv('NVD_API_KEY', None)
        self.session = session

    async def get_vulnerabilities_by_cpe(self, cpe: str) -> List[Dict]:
        """Get vulnerabilities for a specific CPE from NVD API"""
        if not cpe:
            return []

        vulnerabilities = []
        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            params = {'cpeName': cpe, 'resultsPerPage': 100}
            async with self.session.get(self.NVD_BASE_URL, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        vulnerabilities.append({
                            'id': cve.get('id', ''),
                            'description': next((desc['value'] for desc in cve.get('descriptions', [])
                                                if desc['lang'] == 'en'), ''),
                            'cvss_score': float(cve.get('metrics', {})
                                            .get('cvssMetricV31', [{}])[0]
                                            .get('cvssData', {})
                                            .get('baseScore', 0.0)),
                            'severity': cve.get('metrics', {})
                                            .get('cvssMetricV31', [{}])[0]
                                            .get('cvssData', {})
                                            .get('baseSeverity', 'UNKNOWN'),
                            'exploit_available': any('Exploit' in ref.get('tags', [])
                                                    for ref in cve.get('references', []))
                        })
                else:
                    logger.error(f"NVD API error for CPE {cpe}: {response.status}")
        except Exception as e:
            logger.error(f"Failed to get NVD data for CPE {cpe}: {str(e)}")

        return vulnerabilities

# Core Engine
class ADFISEngine:
    """Next-generation cyber intelligence engine"""

    def __init__(self, intensity: ScanIntensity = ScanIntensity.STANDARD):
        self.intensity = intensity
        self.session = None
        self.nvd = None
        self.executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TASKS)
        self.loop = asyncio.get_event_loop()
        self._init_session()
        self.nvd = NVDLoader(self.session)

    def _init_session(self):
        """Initialize aiohttp session with custom headers"""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            headers={'User-Agent': DEFAULT_USER_AGENT},
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=False)
        )

    async def close(self):
        """Cleanup resources"""
        await self.session.close()
        self.executor.shutdown(wait=False)

    async def full_scan(self, target: str) -> Dict:
        """Conduct comprehensive intelligence gathering"""
        scan_report = {
            'metadata': {
                'target': target,
                'start_time': datetime.utcnow().isoformat(),
                'adfis_version': VERSION,
                'scan_intensity': self.intensity.name
            },
            'network': {},
            'web': {},
            'dns': {},
            'threat_assessment': {},
            'recommendations': []
        }

        try:
            # Phase 1: Target validation and metadata collection
            scan_report['metadata'].update(await self._get_target_metadata(target))

            # Phase 2: Network reconnaissance (async)
            network_tasks = [
                self._port_scan(target),
                self._service_detection(target),
                self._os_detection(target),
                self._tls_analysis(target)
            ]
            network_results = await asyncio.gather(*network_tasks, return_exceptions=True)

            scan_report['network'].update({
                'port_scan': network_results[0],
                'services': network_results[1],
                'os_info': network_results[2],
                'tls_info': network_results[3]
            })

            # Phase 3: Web application analysis
            scan_report['web'] = await self._web_analysis(target)

            # Phase 4: DNS reconnaissance
            scan_report['dns'] = await self._dns_recon(target)

            # Phase 5: Threat assessment
            scan_report['threat_assessment'] = self._assess_threats(scan_report)

            # Phase 6: Generate recommendations
            scan_report['recommendations'] = self._generate_recommendations(scan_report)

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            scan_report['error'] = str(e)
            scan_report['status'] = 'failed'
        else:
            scan_report['status'] = 'completed'
            scan_report['metadata']['end_time'] = datetime.utcnow().isoformat()
            scan_report['metadata']['duration'] = str(
                datetime.fromisoformat(scan_report['metadata']['end_time']) -
                datetime.fromisoformat(scan_report['metadata']['start_time'])
            )

        return scan_report

    async def _get_target_metadata(self, target: str) -> Dict:
        """Collect target metadata including WHOIS, ASN, and geolocation"""
        metadata = {
            'ip': None,
            'is_private': False,
            'asn': {},
            'whois': {},
            'geolocation': {}
        }

        try:
            # Resolve target to IP
            metadata['ip'] = await self.loop.run_in_executor(
                self.executor, socket.gethostbyname, target)

            # Check if IP is private
            metadata['is_private'] = ipaddress.ip_address(metadata['ip']).is_private

            # Get WHOIS data
            metadata['whois'] = await self.loop.run_in_executor(
                self.executor, self._get_whois_data, target)

            # Get ASN and geolocation (placeholder for actual API integration)
            metadata['asn'] = await self._get_asn_info(metadata['ip'])
            metadata['geolocation'] = await self._get_geo_info(metadata['ip'])

        except Exception as e:
            logger.warning(f"Metadata collection failed: {str(e)}")

        return metadata

    def _get_whois_data(self, domain: str) -> Dict:
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)

            # The whois library can return a list of dates, take the first one.
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None

            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0] if expiration_date else None

            return {
                'registrar': w.registrar,
                'creation_date': str(creation_date) if creation_date else 'N/A',
                'expiration_date': str(expiration_date) if expiration_date else 'N/A',
                'name_servers': w.name_servers,
                'status': w.status
            }
        except whois.parser.PywhoisError as e:
            logger.warning(f"Could not parse WHOIS data for {domain}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"An unexpected error occurred during WHOIS lookup for {domain}: {e}")
            return {}

    async def _get_asn_info(self, ip: str) -> Dict:
        """Get ASN information for IP using ip-api.com"""
        if not ip or ipaddress.ip_address(ip).is_private:
            return {}
        try:
            url = f"http://ip-api.com/json/{ip}?fields=as,org"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'asn': data.get('as', 'N/A'),
                        'organization': data.get('org', 'N/A')
                    }
                return {}
        except Exception as e:
            logger.warning(f"Failed to get ASN info for {ip}: {e}")
            return {}

    async def _get_geo_info(self, ip: str) -> Dict:
        """Get geolocation info for IP using ip-api.com"""
        if not ip or ipaddress.ip_address(ip).is_private:
            return {}
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,isp"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'country': data.get('country', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'latitude': data.get('lat', 'N/A'),
                        'longitude': data.get('lon', 'N/A'),
                        'isp': data.get('isp', 'N/A')
                    }
                return {}
        except Exception as e:
            logger.warning(f"Failed to get geolocation info for {ip}: {e}")
            return {}

    async def _port_scan(self, target: str) -> Dict:
        """Conduct intelligent port scanning based on intensity level"""
        nm = nmap.PortScanner()
        scan_args = {
            ScanIntensity.LIGHT: '-T3 -F --max-retries 1',
            ScanIntensity.STANDARD: '-T4 -sS -Pn --max-retries 2',
            ScanIntensity.AGGRESSIVE: '-T4 -A -v -Pn --max-retries 3',
            ScanIntensity.PENETRATION: '-T5 -A -v -Pn -sS -sU -p- --max-retries 5'
        }[self.intensity]

        try:
            logger.info(f"Starting {self.intensity.name} port scan on {target}")
            await self.loop.run_in_executor(
                self.executor, nm.scan, target, arguments=scan_args)

            results = {}
            for proto in nm[target].all_protocols():
                for port, data in nm[target][proto].items():
                    results[port] = {
                        'protocol': proto,
                        'state': data['state'],
                        'service': data.get('name', 'unknown')
                    }

            return results
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {}

    async def _service_detection(self, target: str) -> Dict:
        """Detect services with version information and vulnerabilities"""
        nm = nmap.PortScanner()
        # Ensure we get CPEs
        scan_args = '-sV --version-intensity 7'

        try:
            logger.info(f"Starting service detection on {target}")
            await self.loop.run_in_executor(
                self.executor, nm.scan, target, arguments=scan_args)

            services = {}
            # Use a list of tasks to run vulnerability scans concurrently
            tasks = []

            for proto in nm[target].all_protocols():
                for port, data in nm[target][proto].items():
                    cpe = data.get('cpe', '')
                    service = {
                        'name': data['name'],
                        'product': data.get('product', ''),
                        'version': data.get('version', ''),
                        'extrainfo': data.get('extrainfo', ''),
                        'cpe': cpe,
                        'vulnerabilities': []
                    }

                    # Schedule vulnerability scan if CPE is available
                    if cpe:
                        # We need a way to correlate the result back to the service
                        task = asyncio.create_task(self._fetch_service_vulns(cpe, service))
                        tasks.append(task)

                    services[port] = service

            # Wait for all vulnerability scans to complete
            await asyncio.gather(*tasks)

            return services
        except Exception as e:
            logger.error(f"Service detection failed: {str(e)}")
            return {}

    async def _fetch_service_vulns(self, cpe: str, service: Dict):
        """Helper to fetch vulnerabilities and update service dictionary."""
        logger.info(f"Fetching vulnerabilities for CPE: {cpe}")
        vulns = await self.nvd.get_vulnerabilities_by_cpe(cpe)
        if vulns:
            logger.info(f"Found {len(vulns)} vulnerabilities for {service.get('product', cpe)}")
        service['vulnerabilities'] = vulns

    async def _os_detection(self, target: str) -> Dict:
        """Perform OS fingerprinting"""
        nm = nmap.PortScanner()
        scan_args = '-O --osscan-guess'

        try:
            logger.info(f"Starting OS detection on {target}")
            await self.loop.run_in_executor(
                self.executor, nm.scan, target, arguments=scan_args)

            os_info = nm[target].get('osmatch', [{}])[0]
            return {
                'name': os_info.get('name', 'Unknown'),
                'accuracy': os_info.get('accuracy', 0),
                'type': os_info.get('osclass', {}).get('type', 'Unknown'),
                'vendor': os_info.get('osclass', {}).get('vendor', 'Unknown')
            }
        except Exception as e:
            logger.error(f"OS detection failed: {str(e)}")
            return {}

    async def _tls_analysis(self, target: str) -> Dict:
        """Analyze TLS configuration and certificate"""
        try:
            context = ssl.create_default_context()
            # We are not verifying the cert here because we want to analyze it, even if it's self-signed or expired.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Adding a timeout for the socket connection
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    cert_bytes = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bytes)

                    return {
                        'tls_version': ssock.version(),
                        'cipher_suite': cipher[0] if cipher else 'N/A',
                        'certificate_analysis': self._parse_certificate(cert)
                    }
        except ssl.SSLError as e:
            logger.warning(f"TLS/SSL Error for {target}: {e}. The port might not be speaking SSL or has configuration issues.")
            return {'error': 'SSL Error', 'details': str(e)}
        except socket.timeout:
            logger.warning(f"Timeout connecting to {target}:443 for TLS analysis.")
            return {'error': 'Timeout'}
        except Exception as e:
            logger.error(f"TLS analysis failed for {target}: {str(e)}")
            return {'error': str(e)}

    def _parse_certificate(self, cert: x509.Certificate) -> Dict:
        """Parse X.509 certificate details and perform basic analysis"""
        def parse_name(name):
            return {attr.oid._name: attr.value for attr in name}

        now = datetime.utcnow()
        is_expired = now > cert.not_valid_after
        is_not_yet_valid = now < cert.not_valid_before

        # Check for weak signature algorithm (e.g., SHA-1)
        weak_signature = 'sha1' in cert.signature_algorithm_oid._name.lower()

        # Extract public key details
        public_key = cert.public_key()
        key_size = 'N/A'
        key_type = 'N/A'
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = 'RSA'
            key_size = public_key.key_size
        # Can add elif for other key types like EC, DSA etc.

        return {
            'subject': parse_name(cert.subject),
            'issuer': parse_name(cert.issuer),
            'validity': {
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'is_expired': is_expired,
                'is_not_yet_valid': is_not_yet_valid,
            },
            'serial_number': str(cert.serial_number),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'public_key': {
                'type': key_type,
                'size': key_size,
            },
            'security_issues': {
                'weak_signature_algorithm': weak_signature,
                'is_expired': is_expired
            },
            'extensions': [ext.oid._name for ext in cert.extensions]
        }

    async def _web_analysis(self, target: str) -> Dict:
        """Analyze web application security"""
        results = {
            'http': {},
            'https': {},
            'headers': {},
            'technologies': [],
            'security_headers': {},
            'vulnerabilities': [],
            'robots_txt': {}
        }

        try:
            # Check HTTPS first
            https_url = f"https://{target}"
            async with self.session.get(https_url, allow_redirects=True) as resp:
                results['https'] = await self._analyze_response(resp)
                results['headers'] = dict(resp.headers)

                # Check security headers
                results['security_headers'] = {
                    'hsts': 'strict-transport-security' in resp.headers,
                    'csp': 'content-security-policy' in resp.headers,
                    'xss_protection': 'x-xss-protection' in resp.headers,
                    'x_frame_options': 'x-frame-options' in resp.headers,
                    'x_content_type': 'x-content-type-options' in resp.headers
                }

                # Detect technologies
                results['technologies'] = self._detect_technologies(resp)

        except Exception as e:
            logger.debug(f"HTTPS analysis failed: {str(e)}")

            # Fallback to HTTP
            try:
                http_url = f"http://{target}"
                async with self.session.get(http_url, allow_redirects=True) as resp:
                    results['http'] = await self._analyze_response(resp)

                    # Merge headers if HTTPS failed
                    if not results.get('headers'):
                        results['headers'] = dict(resp.headers)
            except Exception as e:
                logger.debug(f"HTTP analysis failed: {str(e)}")

        # Check for common vulnerabilities
        results['vulnerabilities'] = await self._check_web_vulns(target)

        # Analyze robots.txt
        results['robots_txt'] = await self._check_robots_txt(target)

        return results

    async def _analyze_response(self, response) -> Dict:
        """Analyze HTTP response"""
        return {
            'status': response.status,
            'server': response.headers.get('Server', ''),
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': response.headers.get('Content-Length', ''),
            'cookies': dict(response.cookies),
            'redirects': [str(r.url) for r in response.history]
        }

    def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies from response"""
        tech = []

        # From headers
        if 'X-Powered-By' in response.headers:
            tech.append(response.headers['X-Powered-By'])

        # From server header
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            tech.append('Apache')
        elif 'nginx' in server:
            tech.append('Nginx')
        elif 'iis' in server:
            tech.append('IIS')

        # From cookies
        if any('php' in c.lower() for c in dict(response.cookies)):
            tech.append('PHP')

        return tech

    async def _check_web_vulns(self, target: str) -> List[Dict]:
        """Check for common web vulnerabilities"""
        vulns = []

        # Check for SQL injection (simplified)
        test_url = f"http://{target}/?id=1'"
        try:
            async with self.session.get(test_url) as resp:
                if "SQL syntax" in await resp.text():
                    vulns.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'description': 'Potential SQL injection vulnerability detected'
                    })
        except:
            pass

        # Check for XSS (simplified)
        test_url = f"http://{target}/?q=<script>alert(1)</script>"
        try:
            async with self.session.get(test_url) as resp:
                if "<script>alert(1)</script>" in await resp.text():
                    vulns.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'Medium',
                        'confidence': 'Low',
                        'description': 'Potential XSS vulnerability detected'
                    })
        except:
            pass

        return vulns

    async def _check_robots_txt(self, target: str) -> Dict:
        """Fetch and parse the robots.txt file."""
        results = {'disallowed': [], 'allowed': [], 'sitemaps': [], 'found': False}
        # Try both https and http
        for protocol in ["https", "http"]:
            url = f"{protocol}://{target}/robots.txt"
            try:
                # Use a shorter timeout for this specific check
                async with self.session.get(url, timeout=10) as response:
                    if response.status == 200:
                        logger.info(f"Found and parsing robots.txt at {url}")
                        results['found'] = True
                        text = await response.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                directive = parts[0].strip().lower()
                                path = parts[1].strip()
                                if directive == 'disallow':
                                    results['disallowed'].append(path)
                                elif directive == 'allow':
                                    results['allowed'].append(path)
                                elif directive == 'sitemap':
                                    results['sitemaps'].append(path)
                        # If found and parsed, break the loop and return
                        return results
            except asyncio.TimeoutError:
                logger.debug(f"Timeout when trying to fetch {url}")
            except Exception as e:
                logger.debug(f"Could not fetch or parse {url}: {e}")
            continue
        return results

    async def _dns_recon(self, target: str) -> Dict:
        """Perform DNS reconnaissance"""
        domain = target.split(':')[0]  # Remove port if present
        results = {
            'records': {},
            'subdomains': [],
            'zone_transfer': {},
            'dnssec': False
        }

        try:
            # Common record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            for rtype in record_types:
                try:
                    answers = await self.loop.run_in_executor(
                        self.executor, dns.resolver.resolve, domain, rtype)
                    results['records'][rtype] = [str(r) for r in answers]
                except Exception:
                    results['records'][rtype] = []

            # Check DNSSEC
            try:
                answers = await self.loop.run_in_executor(
                    self.executor, dns.resolver.resolve, domain, 'DNSKEY')
                results['dnssec'] = len(answers) > 0
            except Exception:
                results['dnssec'] = False

            # Subdomain enumeration (basic)
            if self.intensity.value >= ScanIntensity.AGGRESSIVE.value:
                common_subdomains = ['www', 'mail', 'admin', 'api', 'dev']
                for sub in common_subdomains:
                    full_sub = f"{sub}.{domain}"
                    try:
                        await self.loop.run_in_executor(
                            self.executor, dns.resolver.resolve, full_sub, 'A')
                        results['subdomains'].append(full_sub)
                    except Exception:
                        continue

            # Zone transfer test
            if 'NS' in results['records']:
                results['zone_transfer'] = await self._test_zone_transfer(
                    domain, results['records']['NS'])

        except Exception as e:
            logger.error(f"DNS reconnaissance failed: {str(e)}")

        return results

    async def _test_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict:
        """Test DNS zone transfer vulnerability"""
        results = {
            'vulnerable': False,
            'successful_transfers': []
        }

        for ns in nameservers:
            try:
                # Get NS IP
                ns_ip = await self.loop.run_in_executor(
                    self.executor, dns.resolver.resolve, ns, 'A')
                ns_ip = str(ns_ip[0])

                # Attempt zone transfer
                zone = await self.loop.run_in_executor(
                    self.executor, dns.zone.from_xfr,
                    dns.query.xfr(ns_ip, domain))

                if zone:
                    results['vulnerable'] = True
                    results['successful_transfers'].append(ns)
            except Exception as e:
                logger.debug(f"Zone transfer failed on {ns}: {str(e)}")
                continue

        return results

    def _assess_threats(self, report: Dict) -> Dict:
        """Analyze collected data and assess threats"""
        threats = {
            'score': 0,
            'level': ThreatLevel.INFO.name,
            'vulnerabilities': [],
            'anomalies': []
        }

        # Calculate base score
        threats['score'] += len(report.get('network', {}).get('port_scan', {})) * 0.5
        threats['score'] += len(report.get('web', {}).get('vulnerabilities', [])) * 1.0
        threats['score'] += len(report.get('dns', {}).get('subdomains', [])) * 0.2

        # Add all vulnerabilities
        for service in report.get('network', {}).get('services', {}).values():
            threats['vulnerabilities'].extend(service.get('vulnerabilities', []))

        threats['vulnerabilities'].extend(report.get('web', {}).get('vulnerabilities', []))

        # Adjust score based on vulnerability severity
        if threats['vulnerabilities']:
            max_cvss = max(v.get('cvss_score', 0) for v in threats['vulnerabilities'])
            threats['score'] *= (1 + max_cvss/10)

        # Determine threat level
        if threats['score'] > 8:
            threats['level'] = ThreatLevel.CRITICAL.name
        elif threats['score'] > 5:
            threats['level'] = ThreatLevel.HIGH.name
        elif threats['score'] > 3:
            threats['level'] = ThreatLevel.MEDIUM.name
        elif threats['score'] > 1:
            threats['level'] = ThreatLevel.LOW.name
        else:
            threats['level'] = ThreatLevel.INFO.name

        return threats

    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate security recommendations"""
        recs = []
        threats = report.get('threat_assessment', {})

        # Critical vulnerabilities
        crit_vulns = [v for v in threats.get('vulnerabilities', [])
                     if v.get('severity') == 'CRITICAL']
        if crit_vulns:
            recs.append(f"Immediately patch {len(crit_vulns)} critical vulnerabilities")

        # Open ports
        open_ports = len(report.get('network', {}).get('port_scan', {}))
        if open_ports > 10:
            recs.append(f"Reduce number of open ports ({open_ports} currently open)")

        # DNS issues
        if report.get('dns', {}).get('zone_transfer', {}).get('vulnerable'):
            recs.append("Restrict DNS zone transfers to authorized servers")

        # Web security
        if not report.get('web', {}).get('security_headers', {}).get('hsts'):
            recs.append("Implement HSTS for HTTPS")

        if not report.get('web', {}).get('security_headers', {}).get('csp'):
            recs.append("Implement Content Security Policy header")

        return recs if recs else ["No critical security issues detected"]

async def main():
    """Command line interface"""
    import argparse

    parser = argparse.ArgumentParser(
        description=f"ADFIS {VERSION} - Next Generation Cyber Intelligence Platform",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-o", "--output", default="report.json",
                       help="Output JSON file")
    parser.add_argument("-i", "--intensity", type=int, choices=range(1, 5), default=2,
                       help="Scan intensity (1=Light, 4=Penetration)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    engine = None
    try:
        logger.info(f"Starting ADFIS {VERSION} scan for {args.target}")
        logger.info(f"Scan intensity: {ScanIntensity(args.intensity).name}")

        engine = ADFISEngine(ScanIntensity(args.intensity))
        report = await engine.full_scan(args.target)

        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Scan completed. Report saved to {args.output}")

        # Print summary
        logger.info("\n=== Scan Summary ===")
        logger.info(f"Target: {report['metadata']['target']}")
        logger.info(f"Status: {report.get('status', 'unknown')}")
        logger.info(f"Threat Level: {report.get('threat_assessment', {}).get('level', 'UNKNOWN')}")

        vulns = report.get('threat_assessment', {}).get('vulnerabilities', [])
        if vulns:
            logger.info(f"Vulnerabilities found: {len(vulns)}")
            for v in vulns[:3]:  # Show top 3
                logger.info(f"- {v.get('id', 'Unknown')} ({v.get('severity')}): {v.get('description')[:60]}...")

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
    finally:
        if engine:
            await engine.close()

if __name__ == "__main__":
    asyncio.run(main())
