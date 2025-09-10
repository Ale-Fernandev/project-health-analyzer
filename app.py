from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
import json
from utils.github_analyzer import GitHubAnalyzer
from utils.security_scanner import SecurityScanner
from utils.ai_analyzer import AIAnalyzer

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-this')

# Initialize analyzer components
github_analyzer = GitHubAnalyzer(os.getenv('GITHUB_TOKEN'))
security_scanner = SecurityScanner(os.getenv('GITHUB_TOKEN'))
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
        
        # Step 2: Perform enhanced security scanning with GHSA/NVD
        security_issues = security_scanner.scan_repository_enhanced(owner, repo_name, repo_data)
        
        # Step 3: Check dependencies with vulnerability detection
        dependency_report = github_analyzer.check_dependencies_with_vulnerabilities(owner, repo_name)
        
        # Step 4: Analyze CI/CD pipeline
        ci_cd_health = github_analyzer.check_ci_cd(owner, repo_name)
        
        # Step 5: Check documentation
        docs_report = github_analyzer.check_documentation(owner, repo_name)
        
        # Step 6: Use AI to calculate health score and generate insights
        all_data = {
            'repo_data': repo_data,
            'security_issues': security_issues,
            'dependencies': dependency_report,
            'ci_cd': ci_cd_health,
            'documentation': docs_report
        }
        
        # AI-powered health score calculation
        health_score = ai_analyzer.calculate_health_score_ai(all_data)
        
        # Generate AI insights
        ai_insights = ai_analyzer.generate_insights(all_data)
        
        # Generate recommendations based on AI analysis
        recommendations = generate_recommendations_ai(
            security_issues, 
            dependency_report, 
            ci_cd_health, 
            docs_report,
            health_score
        )
        
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
            'issues': {
                'security': security_issues,
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

def generate_recommendations_ai(security, dependencies, ci_cd, docs, health_score):
    """Generate actionable recommendations based on AI-powered analysis."""
    recommendations = []
    
    # Critical recommendations for low health scores
    if health_score < 40:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Overall Health',
            'message': f'Repository health is critical ({health_score}/100)',
            'action': 'This repository requires immediate attention or should be replaced with an actively maintained alternative.'
        })
    
    # Security recommendations
    if security.get('ghsa_alerts', []):
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Security',
            'message': f"{len(security.get('ghsa_alerts', []))} GitHub Security Advisories detected",
            'action': 'Review and patch security vulnerabilities immediately. Check GHSA alerts for specific CVEs.'
        })
    
    if security.get('critical_issues', 0) > 0:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Security',
            'message': f"{security.get('critical_issues')} critical security vulnerabilities detected",
            'action': 'Address critical security issues before deployment.'
        })
    
    # Dependency recommendations
    vulnerable_deps = dependencies.get('vulnerable_dependencies', [])
    if vulnerable_deps:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Dependencies',
            'message': f"{len(vulnerable_deps)} vulnerable dependencies found",
            'action': f"Update vulnerable packages: {', '.join([d['name'] for d in vulnerable_deps[:3]])}{'...' if len(vulnerable_deps) > 3 else ''}"
        })
    
    outdated = dependencies.get('outdated_count', 0)
    if outdated > 10:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Dependencies',
            'message': f"{outdated} outdated dependencies detected",
            'action': 'Run dependency updates and test thoroughly. Consider using automated dependency management tools.'
        })
    
    # CI/CD recommendations
    if not ci_cd.get('has_ci_cd', False):
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'CI/CD',
            'message': 'No CI/CD pipeline detected',
            'action': 'Implement GitHub Actions or another CI/CD solution for automated testing and deployment.'
        })
    elif ci_cd.get('last_run_status') == 'failure':
        recommendations.append({
            'priority': 'HIGH',
            'category': 'CI/CD',
            'message': 'CI/CD pipeline is failing',
            'action': 'Fix failing tests and builds to ensure code quality.'
        })
    
    # Documentation recommendations
    if not docs.get('has_readme', False):
        recommendations.append({
            'priority': 'LOW',
            'category': 'Documentation',
            'message': 'README file is missing',
            'action': 'Add comprehensive README with installation, usage, and contribution guidelines.'
        })
    
    # Age-based recommendations
    days_old = dependencies.get('days_since_update', 0)
    if days_old > 730:  # 2+ years
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Maintenance',
            'message': f'Repository has not been updated in {days_old // 365} years',
            'action': 'Consider forking and modernizing, or finding an actively maintained alternative.'
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
    app.run(debug=True, port=5000)