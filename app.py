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
github_token = os.getenv('GITHUB_TOKEN')
google_api_key = os.getenv('GOOGLE_API_KEY')

if not github_token:
    print("⚠ WARNING: GITHUB_TOKEN not found in environment variables")
if not google_api_key:
    print("⚠ WARNING: GOOGLE_API_KEY not found in environment variables")
    print("   AI analysis will not be available - fallback mode will be used")

github_analyzer = GitHubAnalyzer(github_token)
security_scanner = SecurityScanner(github_token)
ai_analyzer = AIAnalyzer(google_api_key) if google_api_key else None

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
        parts = repo_url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
        if len(parts) < 2:
            return jsonify({'error': 'Invalid GitHub URL format'}), 400
        
        owner = parts[0]
        repo_name = parts[1].replace('.git', '')
        
        print(f"\n{'='*60}")
        print(f"Starting analysis for: {owner}/{repo_name}")
        print(f"{'='*60}\n")
        
        # Step 1: Fetch repository data
        print("Step 1: Fetching repository data...")
        repo_data = github_analyzer.fetch_repo_data(owner, repo_name)
        
        # Step 2: Perform enhanced security scanning
        print("Step 2: Scanning for security issues...")
        security_issues = security_scanner.scan_repository_enhanced(owner, repo_name, repo_data)
        
        # Step 3: Check dependencies
        print("Step 3: Analyzing dependencies...")
        dependency_report = github_analyzer.check_dependencies_with_vulnerabilities(owner, repo_name)
        
        # Step 4: Analyze CI/CD pipeline
        print("Step 4: Checking CI/CD configuration...")
        ci_cd_health = github_analyzer.check_ci_cd(owner, repo_name)
        
        # Step 5: Check documentation
        print("Step 5: Evaluating documentation...")
        docs_report = github_analyzer.check_documentation(owner, repo_name)
        
        # Compile all data for AI analysis
        all_data = {
            'repo_data': repo_data,
            'security_issues': security_issues,
            'dependencies': dependency_report,
            'ci_cd': ci_cd_health,
            'documentation': docs_report
        }
        
        # Step 6: AI-powered analysis
        print("Step 6: Performing AI analysis...")
        
        if ai_analyzer:
            # Calculate health score using AI
            health_score = ai_analyzer.calculate_health_score_ai(all_data)
            
            # Generate AI insights
            ai_insights = ai_analyzer.generate_insights(all_data)
            
            # Get AI status
            ai_status = ai_analyzer.get_ai_status_message()
        else:
            print("⚠ AI Analyzer not available (no API key) - using fallback methods")
            health_score = calculate_fallback_score(all_data)
            ai_insights = generate_basic_insights(all_data)
            ai_status = {
                'ai_used': False,
                'message': '⚠️ AI Analysis Unavailable',
                'description': 'GOOGLE_API_KEY not configured. Using rule-based analysis.',
                'recommendation': 'Add GOOGLE_API_KEY to .env file to enable AI-powered insights.'
            }
        
        # Step 7: Generate recommendations
        print("Step 7: Generating recommendations...")
        recommendations = generate_recommendations(
            security_issues, 
            dependency_report, 
            ci_cd_health, 
            docs_report,
            health_score
        )
        
        print(f"\n{'='*60}")
        print(f"✓ Analysis complete! Health Score: {health_score}/100")
        print(f"{'='*60}\n")
        
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
                'days_since_update': repo_data.get('days_since_activity', 'Unknown'),
                'archived': repo_data.get('archived', False)
            },
            'health_score': health_score,
            'issues': {
                'security': security_issues,
                'dependencies': dependency_report,
                'ci_cd': ci_cd_health,
                'documentation': docs_report
            },
            'ai_insights': ai_insights,
            'ai_status': ai_status,
            'recommendations': recommendations
        }
        
        return jsonify(analysis_report)
        
    except Exception as e:
        app.logger.error(f"Error analyzing repository: {str(e)}")
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f"Failed to analyze repository: {str(e)}"
        }), 500

def calculate_fallback_score(all_data):
    """Calculate health score without AI."""
    score = 100
    
    repo_data = all_data.get('repo_data', {})
    security = all_data.get('security_issues', {})
    deps = all_data.get('dependencies', {})
    
    days_old = repo_data.get('days_since_activity', 0)
    
    if repo_data.get('archived'):
        return 20
    
    # Security penalties
    score -= security.get('critical_issues', 0) * 30
    score -= len(security.get('ghsa_alerts', [])) * 25
    score -= security.get('high_issues', 0) * 15
    
    # Age penalties
    if days_old > 1095:
        score = min(score, 30)
    elif days_old > 730:
        score = min(score, 45)
    elif days_old > 365:
        score = min(score, 60)
    
    # Dependency penalties
    score -= deps.get('vulnerable_count', 0) * 10
    score -= min(20, deps.get('outdated_count', 0) // 2)
    
    return max(0, min(100, score))

def generate_basic_insights(all_data):
    """Generate basic insights without AI."""
    insights = []
    
    repo_data = all_data.get('repo_data', {})
    days_old = repo_data.get('days_since_activity', 0)
    
    if days_old > 730:
        insights.append(f"Repository has been inactive for {days_old // 365} years and likely contains unpatched vulnerabilities.")
    
    security = all_data.get('security_issues', {})
    if security.get('critical_issues', 0) > 0:
        insights.append(f"Critical security issues detected requiring immediate attention.")
    
    deps = all_data.get('dependencies', {})
    if deps.get('vulnerable_count', 0) > 0:
        insights.append(f"{deps.get('vulnerable_count')} vulnerable dependencies need updating.")
    
    if not insights:
        insights.append("Basic analysis complete. Enable AI for detailed insights.")
    
    return insights[:4]

def generate_recommendations(security, dependencies, ci_cd, docs, health_score):
    """Generate actionable recommendations."""
    recommendations = []
    
    # Critical health score
    if health_score < 40:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Overall Health',
            'message': f'Repository health is critical ({health_score}/100)',
            'action': 'This repository requires immediate attention or should be replaced with an actively maintained alternative.'
        })
    
    # GHSA alerts
    ghsa_alerts = security.get('ghsa_alerts', [])
    if ghsa_alerts:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Security',
            'message': f"{len(ghsa_alerts)} GitHub Security Advisories detected",
            'action': 'Review and patch security vulnerabilities immediately. Check GHSA alerts for specific CVEs.'
        })
    
    # Critical security issues
    if security.get('critical_issues', 0) > 0:
        recommendations.append({
            'priority': 'CRITICAL',
            'category': 'Security',
            'message': f"{security.get('critical_issues')} critical security vulnerabilities detected",
            'action': 'Address critical security issues before any deployment.'
        })
    
    # Vulnerable dependencies
    vulnerable_deps = dependencies.get('vulnerable_dependencies', [])
    if vulnerable_deps:
        pkg_names = [d['name'] for d in vulnerable_deps[:3]]
        more_text = f' and {len(vulnerable_deps) - 3} more' if len(vulnerable_deps) > 3 else ''
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Dependencies',
            'message': f"{len(vulnerable_deps)} vulnerable dependencies found",
            'action': f"Update vulnerable packages: {', '.join(pkg_names)}{more_text}"
        })
    
    # Outdated dependencies
    outdated = dependencies.get('outdated_count', 0)
    if outdated > 10:
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'Dependencies',
            'message': f"{outdated} outdated dependencies detected",
            'action': 'Run dependency updates and test thoroughly. Consider automated dependency management.'
        })
    
    # CI/CD issues
    if not ci_cd.get('has_ci_cd', False):
        recommendations.append({
            'priority': 'MEDIUM',
            'category': 'CI/CD',
            'message': 'No CI/CD pipeline detected',
            'action': 'Implement GitHub Actions or another CI/CD solution for automated testing.'
        })
    elif ci_cd.get('last_run_status') == 'failure':
        recommendations.append({
            'priority': 'HIGH',
            'category': 'CI/CD',
            'message': 'CI/CD pipeline is failing',
            'action': 'Fix failing tests and builds to ensure code quality.'
        })
    
    # Documentation
    if not docs.get('has_readme', False):
        recommendations.append({
            'priority': 'LOW',
            'category': 'Documentation',
            'message': 'README file is missing',
            'action': 'Add comprehensive README with installation and usage instructions.'
        })
    
    # Repository age
    days_old = dependencies.get('days_since_update', 0)
    if days_old > 730:
        recommendations.append({
            'priority': 'HIGH',
            'category': 'Maintenance',
            'message': f'Repository abandoned for {days_old // 365} years',
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
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)