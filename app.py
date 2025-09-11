from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
import json
from utils.github_analyzer import GitHubAnalyzer
from utils.security_scanner import SecurityScanner
from utils.ai_analyzer import AIAnalyzer
from utils.vulnerability_scanner import VulnerabilityScanner

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-this')

# Initialize analyzer components
github_analyzer = GitHubAnalyzer(os.getenv('GITHUB_TOKEN'))
security_scanner = SecurityScanner(os.getenv('GITHUB_TOKEN'))
vulnerability_scanner = VulnerabilityScanner(os.getenv('GITHUB_TOKEN'))
ai_analyzer = AIAnalyzer(os.getenv('GOOGLE_API_KEY'))

@app.route('/')
def index():
    """Renders the main page of the application."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_repo():
    """Main endpoint for repository analysis."""
    try:
        data = request.get_json()
        repo_url = data.get('repo_url')
        
        if not repo_url:
            return jsonify({'error': 'No repository URL provided'}), 400
        
        # Extract owner and repo name from URL
        parts = repo_url.replace('https://github.com/', '').split('/')
        if len(parts) < 2:
            return jsonify({'error': 'Invalid GitHub URL format'}), 400
        
        owner = parts[0]
        repo_name = parts[1].replace('.git', '')
        
        # Step 1: Fetch repository data
        repo_data = github_analyzer.fetch_repo_data(owner, repo_name)
        
        # Step 2: Security scanning
        security_issues = security_scanner.scan_repository_enhanced(owner, repo_name, repo_data)
        
        # Step 3: Check dependencies with vulnerability detection
        dependency_report = github_analyzer.check_dependencies_with_vulnerabilities(owner, repo_name)
        
        # Step 4: Vulnerability Scanning
        vulnerability_report = vulnerability_scanner.scan_for_vulnerabilities(
            owner,
            repo_name,
            dependency_report,
            repo_data.get('language', 'Unknown')
        )

        # Step 5: Analyze CI/CD pipeline
        ci_cd_health = github_analyzer.check_ci_cd(owner, repo_name)
        
        # Step 6: Check documentation
        docs_report = github_analyzer.check_documentation(owner, repo_name)
        
        # Merge vulnerability data into security issues
        security_issues['vulnerability_scan'] = vulnerability_report
        security_issues['critical_issues'] += len(vulnerability_report['critical'])
        security_issues['high_issues'] += len(vulnerability_report['high'])
        security_issues['medium_issues'] += len(vulnerability_report['medium'])
        security_issues['low_issues'] += len(vulnerability_report['low'])

        # Package ALL data for AI
        all_data = {
            'repo_data': repo_data,
            'security_issues': security_issues,
            'vulnerability_scan': vulnerability_report,
            'dependencies': dependency_report,
            'ci_cd': ci_cd_health,
            'documentation': docs_report
        }
        
        # Create enhanced prompt for AI with vulnerability focus
        enhanced_prompt_data = {
            **all_data,
            'vulnerability_summary': {
                'total': sum([
                    len(vulnerability_report['critical']),
                    len(vulnerability_report['high']),
                    len(vulnerability_report['medium']),
                    len(vulnerability_report['low'])
                ]),
                'critical_cves': [v.get('cve', 'Unknown') for v in vulnerability_report['critical'][:5]],
                'affected_packages': list(set([v.get('package', 'Unknown') 
                                              for v in vulnerability_report['critical'] + vulnerability_report['high']]))[:10]
            }
        }

        # AI-powered health score calculation
        health_score = ai_analyzer.calculate_health_score_ai(enhanced_prompt_data)
        
        # Generate AI insights
        ai_insights = ai_analyzer.generate_insights(enhanced_prompt_data)

        # Get AI verdict
        verdict = ai_analyzer.generate_verdict(enhanced_prompt_data, health_score)

        # Get any additional concerns AI might spot
        additional_concerns = ai_analyzer.analyze_specific_concerns(enhanced_prompt_data)
        
        # Generate recommendations based on AI analysis
        recommendations = generate_recommendations(
            security_issues,
            vulnerability_report, 
            dependency_report, 
            ci_cd_health, 
            docs_report,
            health_score
        )
        
        if verdict:
            ai_insights.insert(0, verdict)

        if additional_concerns and additional_concerns != "No additional concerns":
            ai_insights.append(f"Additional concern: {additional_concerns}")
        

        # Compile final report
        analysis_report = {
            'success': True,
            'repository': {
                'name': repo_name,
                'owner': owner,
                'url': repo_url,
                'stars': repo_data.get('stars', 0),
                'language': repo_data.get('language', 'Unknown'),
                'last_updated': repo_data.get('updated_at', 'Unknown'),
                'days_since_update': repo_data.get('days_since_update', 'Unknown')
            },
            'health_score': health_score,
            'verdict': verdict,
            'vulnerability_summary': {
                'total_vulnerabilities': sum([
                    len(vulnerability_report['critical']),
                    len(vulnerability_report['high']),
                    len(vulnerability_report['medium']),
                    len(vulnerability_report['low'])
                ]),
                'critical': len(vulnerability_report['critical']),
                'high': len(vulnerability_report['high']),
                'sources_checked': ['GHSA', 'Dependabot', 'OSV','Known CVEs']
            },
            'issues': {
                'security': security_issues,
                'vulnerabilities': vulnerability_scanner.generate_vulnerability_report(vulnerability_report),
                'dependencies': dependency_report,
                'ci_cd': ci_cd_health,
                'documentation': docs_report
            },
            'ai_insights': ai_insights,
            'recommendations': recommendations
        }
        
        return jsonify(analysis_report)
        
    except Exception as e:
        app.logger.error(f"Error analyzing repository: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Failed to analyze repository: {str(e)}"
        }), 500

def generate_recommendations(vulnerability_report, security, dependencies, health_score):
    """Generate recommendations specifically focused on vulnerabilities."""
    recommendations = []
    
    # Critical vulnerabilities - MOST IMPORTANT
    if vulnerability_report['critical']:
        cve_list = [v.get('cve', 'Unknown') for v in vulnerability_report['critical'][:3]]
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Vulnerabilities',
            'message': f"{len(vulnerability_report['critical'])} critical vulnerabilities detected",
            'action': f"Immediately patch: {', '.join(cve_list)}",
            'severity': 'critical'
        })
    
    # High vulnerabilities
    if vulnerability_report['high']:
        affected_packages = list(set([v.get('package', 'Unknown') for v in vulnerability_report['high']]))[:3]
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Vulnerabilities',
            'message': f"{len(vulnerability_report['high'])} high-severity vulnerabilities found",
            'action': f"Update packages: {', '.join(affected_packages)}",
            'severity': 'high'
        })
    
    # GHSA specific alerts
    ghsa_alerts = vulnerability_report.get('ghsa_advisories', [])
    if ghsa_alerts:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'GitHub Security',
            'message': f"{len(ghsa_alerts)} GitHub Security Advisories active",
            'action': 'Review GHSA alerts and apply recommended patches',
            'severity': 'high'
        })
    
    # Vulnerable dependencies
    vuln_deps = dependencies.get('vulnerable_dependencies', [])
    if vuln_deps:
        dep_names = [d['name'] for d in vuln_deps[:3]]
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Dependencies',
            'message': f"{len(vuln_deps)} dependencies with known vulnerabilities",
            'action': f"Update: {', '.join(dep_names)}{'...' if len(vuln_deps) > 3 else ''}",
            'severity': 'high'
        })
    
    # Overall security posture
    total_vulns = sum([
        len(vulnerability_report['critical']),
        len(vulnerability_report['high']),
        len(vulnerability_report['medium']),
        len(vulnerability_report['low'])
    ])
    
    if total_vulns > 20:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Overall Security',
            'message': f'Total of {total_vulns} vulnerabilities detected',
            'action': 'This repository requires immediate security overhaul or should be replaced',
            'severity': 'critical'
        })
    elif total_vulns > 10:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Overall Security',
            'message': f'{total_vulns} total vulnerabilities need attention',
            'action': 'Schedule security sprint to address vulnerabilities',
            'severity': 'high'
        })
    
    # If no vulnerabilities found (good news!)
    if total_vulns == 0:
        recommendations.append({
            'priority': 'LOW',
            'category': 'Security',
            'message': 'No known vulnerabilities detected',
            'action': 'Excellent! Continue with regular security audits',
            'severity': 'info'
        })
    
    return recommendations

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)