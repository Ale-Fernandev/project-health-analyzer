import re
import base64
import requests
from datetime import datetime, timezone

class SecurityScanner:
    """Enhanced security scanner with GitHub Security Advisory integration."""
    
    def __init__(self, github_token=None):
        """Initialize with optional GitHub token for enhanced scanning."""
        self.github_token = github_token
        self.headers = {}
        if github_token:
            self.headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        
        # Enhanced patterns for secret detection
        self.secret_patterns = {
            'api_key': [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}["\']?',
                r'["\']?apikey["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{32,}["\']?',
                r'X-API-Key:\s*[a-zA-Z0-9]{20,}',
            ],
            'aws_key': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}["\']?',
                r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9/+=]{40}["\']?',
            ],
            'github_token': [
                r'ghp_[a-zA-Z0-9]{36}',
                r'gho_[a-zA-Z0-9]{36}',
                r'ghs_[a-zA-Z0-9]{36}',
                r'github[_-]?token\s*[:=]\s*["\']?[a-zA-Z0-9]{40}["\']?',
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\-_]{35}',
            ],
            'private_key': [
                r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
            ],
            'jwt_token': [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            ],
            'slack_token': [
                r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}',
            ],
            'stripe_key': [
                r'sk_live_[a-zA-Z0-9]{24,}',
                r'pk_live_[a-zA-Z0-9]{24,}',
            ]
        }
    
    def scan_repository_enhanced(self, owner, repo_name, repo_data):
        """Enhanced security scan with GHSA integration."""
        security_report = {
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'exposed_secrets': False,
            'vulnerable_dependencies': [],
            'ghsa_alerts': [],
            'security_score': 100,
            'issues_found': [],
            'recommendations': []
        }
        
        # Check GitHub Security Advisories (GHSA)
        if self.github_token:
            ghsa_alerts = self._check_github_security_advisories(owner, repo_name)
            if ghsa_alerts:
                security_report['ghsa_alerts'] = ghsa_alerts
                security_report['critical_issues'] += len([a for a in ghsa_alerts if a.get('severity') == 'critical'])
                security_report['high_issues'] += len([a for a in ghsa_alerts if a.get('severity') == 'high'])
                security_report['medium_issues'] += len([a for a in ghsa_alerts if a.get('severity') == 'medium'])
                security_report['low_issues'] += len([a for a in ghsa_alerts if a.get('severity') == 'low'])
                
                for alert in ghsa_alerts:
                    security_report['issues_found'].append({
                        'type': 'ghsa_vulnerability',
                        'severity': alert.get('severity', 'unknown'),
                        'description': f"GHSA Alert: {alert.get('summary', 'Security vulnerability detected')}",
                        'cve': alert.get('cve_id', 'N/A'),
                        'recommendation': f"Update {alert.get('package', 'affected package')} to {alert.get('patched_version', 'latest version')}"
                    })
        
        # Check repository characteristics
        if repo_data.get('archived'):
            security_report['high_issues'] += 1
            security_report['issues_found'].append({
                'type': 'archived_repo',
                'severity': 'high',
                'description': 'Repository is archived and no longer maintained',
                'recommendation': 'Archived repositories do not receive security updates. Consider migration.'
            })
        
        # Check for stale repository
        days_old = repo_data.get('days_since_activity', 0)
        if days_old > 1095:  # 3+ years
            security_report['high_issues'] += 1
            security_report['issues_found'].append({
                'type': 'abandoned_repository',
                'severity': 'high',
                'description': f'Repository has not been updated in {days_old // 365} years',
                'recommendation': 'Abandoned repositories likely contain unpatched vulnerabilities.'
            })
        elif days_old > 730:  # 2+ years
            security_report['medium_issues'] += 1
            security_report['issues_found'].append({
                'type': 'stale_repository',
                'severity': 'medium',
                'description': f'Repository last updated {days_old // 365} years ago',
                'recommendation': 'Review for security vulnerabilities and consider modernization.'
            })
        elif days_old > 365:  # 1+ year
            security_report['low_issues'] += 1
            security_report['issues_found'].append({
                'type': 'aging_repository',
                'severity': 'low',
                'description': f'Repository last updated {days_old // 30} months ago',
                'recommendation': 'Check for security updates and dependency patches.'
            })
        
        # Language-specific security checks
        language = repo_data.get('language', '').lower()
        
        if language in ['javascript', 'typescript']:
            security_report['medium_issues'] += 1
            security_report['issues_found'].append({
                'type': 'dependency_audit_needed',
                'severity': 'medium',
                'description': 'JavaScript/TypeScript projects require regular security audits',
                'recommendation': 'Run "npm audit" or "yarn audit" to check for vulnerabilities.'
            })
            
            # Check for web application specific issues
            if any(topic in str(repo_data.get('topics', [])).lower() 
                   for topic in ['react', 'vue', 'angular', 'express', 'next', 'nuxt']):
                security_report['issues_found'].append({
                    'type': 'web_security',
                    'severity': 'low',
                    'description': 'Web application detected - requires security headers and CSP',
                    'recommendation': 'Implement Content Security Policy, XSS protection, and security headers.'
                })
        
        elif language == 'python':
            if days_old > 180:
                security_report['low_issues'] += 1
                security_report['issues_found'].append({
                    'type': 'python_security',
                    'severity': 'low',
                    'description': 'Python dependencies may have security updates',
                    'recommendation': 'Use "pip-audit" or "safety check" to scan for vulnerabilities.'
                })
        
        elif language == 'php':
            security_report['medium_issues'] += 1
            security_report['issues_found'].append({
                'type': 'php_security',
                'severity': 'medium',
                'description': 'PHP applications require careful security review',
                'recommendation': 'Check for SQL injection, XSS, and outdated PHP version vulnerabilities.'
            })
        
        elif language in ['java', 'kotlin']:
            if days_old > 365:
                security_report['medium_issues'] += 1
                security_report['issues_found'].append({
                    'type': 'java_security',
                    'severity': 'medium',
                    'description': 'Java dependencies may contain Log4j or Spring vulnerabilities',
                    'recommendation': 'Check for CVE-2021-44228 (Log4Shell) and Spring4Shell vulnerabilities.'
                })
        
        # Check for missing security policy
        if not repo_data.get('has_security_policy', False):
            security_report['low_issues'] += 1
            security_report['issues_found'].append({
                'type': 'missing_security_policy',
                'severity': 'low',
                'description': 'No SECURITY.md file found',
                'recommendation': 'Add a security policy with vulnerability disclosure instructions.'
            })
        
        # Check open issues for security keywords
        open_issues = repo_data.get('open_issues', 0)
        if open_issues > 100:
            security_report['low_issues'] += 1
            security_report['issues_found'].append({
                'type': 'many_open_issues',
                'severity': 'low',
                'description': f'{open_issues} open issues may include security vulnerabilities',
                'recommendation': 'Review issues for security-related reports and CVEs.'
            })
        
        # Large repository check
        if repo_data.get('size', 0) > 100000:
            security_report['low_issues'] += 1
            security_report['issues_found'].append({
                'type': 'large_codebase',
                'severity': 'low',
                'description': 'Large repository may contain overlooked sensitive data',
                'recommendation': 'Run secret scanning tools like TruffleHog or GitLeaks.'
            })
        
        # Calculate security score
        security_report['security_score'] = max(0, 100 - 
            (security_report['critical_issues'] * 30) -
            (security_report['high_issues'] * 20) -
            (security_report['medium_issues'] * 10) -
            (security_report['low_issues'] * 5)
        )
        
        # Generate recommendations
        if security_report['critical_issues'] > 0:
            security_report['recommendations'].append(
                'CRITICAL: Address security vulnerabilities immediately before deployment.'
            )
        
        if days_old > 730:
            security_report['recommendations'].append(
                'Consider a comprehensive security audit for this aging repository.'
            )
        
        if not security_report['issues_found']:
            security_report['recommendations'].append(
                'No immediate security issues detected. Continue with regular security audits.'
            )
        
        return security_report
    
    def _check_github_security_advisories(self, owner, repo_name):
        """Check for GitHub Security Advisories (GHSA) for the repository."""
        alerts = []
        
        try:
            # GitHub API endpoint for vulnerability alerts
            url = f"https://api.github.com/repos/{owner}/{repo_name}/vulnerability-alerts"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 204:
                print(f"Vulnerability alerts enabled for {owner}/{repo_name}")
            
            # Try to get dependabot alerts (requires security permissions)
            dependabot_url = f"https://api.github.com/repos/{owner}/{repo_name}/dependabot/alerts"
            dep_response = requests.get(dependabot_url, headers=self.headers)
            
            if dep_response.status_code == 200:
                dependabot_alerts = dep_response.json()
                for alert in dependabot_alerts:
                    if alert.get('state') == 'open':
                        alerts.append({
                            'type': 'dependabot',
                            'package': alert.get('security_advisory', {}).get('package', {}).get('name', 'Unknown'),
                            'severity': alert.get('security_advisory', {}).get('severity', 'unknown').lower(),
                            'summary': alert.get('security_advisory', {}).get('summary', 'Security vulnerability'),
                            'cve_id': alert.get('security_advisory', {}).get('cve_id', 'N/A'),
                            'patched_version': alert.get('security_advisory', {}).get('first_patched_version', {}).get('identifier', 'latest')
                        })
                        print(f"Found GHSA alert: {alert.get('security_advisory', {}).get('cve_id', 'Unknown CVE')}")
            
            # Try code scanning alerts
            code_scanning_url = f"https://api.github.com/repos/{owner}/{repo_name}/code-scanning/alerts"
            code_response = requests.get(code_scanning_url, headers=self.headers)
            
            if code_response.status_code == 200:
                code_alerts = code_response.json()
                for alert in code_alerts:
                    if alert.get('state') == 'open':
                        severity = alert.get('rule', {}).get('severity', 'unknown').lower()
                        if severity in ['error', 'critical']:
                            severity = 'critical'
                        elif severity == 'warning':
                            severity = 'high'
                        
                        alerts.append({
                            'type': 'code_scanning',
                            'severity': severity,
                            'summary': alert.get('rule', {}).get('description', 'Code vulnerability detected'),
                            'location': alert.get('most_recent_instance', {}).get('location', {}).get('path', 'Unknown')
                        })
            
        except Exception as e:
            print(f"Could not fetch GHSA data: {e}")
        
        return alerts
    
    def check_file_for_secrets(self, file_content):
        """Check file content for exposed secrets."""
        detected_secrets = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, file_content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    detected_secrets.append({
                        'type': secret_type,
                        'count': len(matches),
                        'severity': 'critical' if secret_type != 'api_key' else 'high'
                    })
        
        return detected_secrets
    
    def generate_security_recommendations(self, security_report):
        """Generate actionable security recommendations."""
        recommendations = []
        
        if security_report.get('ghsa_alerts'):
            recommendations.append({
                'priority': 'CRITICAL',
                'action': f"Address {len(security_report['ghsa_alerts'])} GitHub Security Advisories immediately",
                'category': 'GHSA Vulnerabilities'
            })
        
        if security_report['exposed_secrets']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Remove exposed secrets and rotate all credentials immediately',
                'category': 'Secrets Management'
            })
        
        if security_report['critical_issues'] > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Fix critical security vulnerabilities before any deployment',
                'category': 'Security Vulnerabilities'
            })
        
        if security_report['high_issues'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Address high-severity issues within the next sprint',
                'category': 'Security Issues'
            })
        
        if security_report['security_score'] < 50:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Conduct comprehensive security audit and implement security best practices',
                'category': 'Overall Security'
            })
        
        return recommendations