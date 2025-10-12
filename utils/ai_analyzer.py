import google.generativeai as genai
import json
import re

class AIAnalyzer:
    """AI-powered analyzer using Google's Gemini 2.5 Flash for intelligent scoring and insights."""
    
    def __init__(self, api_key):
        """Initialize with Google's Gemini API."""
        if not api_key:
            raise ValueError("Google API key is required for AI analysis")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.ai_available = True
        print("✓ Gemini 2.5 Flash initialized successfully")
        
    def calculate_health_score_ai(self, analysis_data):
        """Use AI to intelligently analyze repository health and provide a reasoned score."""
        try:
            # Create a comprehensive data snapshot for the AI
            data_summary = self._format_analysis_data(analysis_data)
            
            prompt = f"""You are a senior software engineer and security analyst evaluating a GitHub repository. 

I'm providing you with comprehensive data about a repository. Please analyze it thoughtfully and provide a health score from 0-100.

{data_summary}

Consider these aspects in your analysis:

1. **Security Posture**: Are there critical vulnerabilities? Security advisories? How severe are they?

2. **Maintenance & Activity**: 
   - When was this last updated? Is it abandoned or actively maintained?
   - Is it archived? That's a critical red flag.
   - Does the activity level match the project's popularity?

3. **Dependencies**: 
   - How many dependencies are outdated or vulnerable?
   - Are the vulnerabilities critical CVEs or minor issues?
   - What's the actual risk level?

4. **Code Quality Indicators**:
   - Is there automated testing (CI/CD)?
   - Is it passing or failing?
   - Is there documentation?

5. **Context Matters**:
   - A popular project (10k+ stars) with recent activity but failing CI might still be healthy
   - An unpopular project (few stars) abandoned for 2 years is probably dead
   - Some old projects are "done" and don't need updates (like stable utilities)

Think like an engineer making a decision: Would you trust this repository in production? Would you fork it or find an alternative? What's the real risk here?

Provide your health score (0-100) as a single integer, followed by a brief one-sentence explanation of your reasoning.

Example format:
72
This repository is moderately healthy with regular updates and good community support, but has 5 outdated dependencies that should be addressed soon."""

            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Parse the response - expecting score on first line
            lines = response_text.split('\n')
            score_line = lines[0].strip()
            
            # Extract the score
            score_match = re.search(r'\b(\d+)\b', score_line)
            if not score_match:
                raise ValueError(f"Could not extract score from response: {response_text}")
            
            score = int(score_match.group(1))
            score = max(0, min(100, score))
            
            # Get the reasoning (everything after the score)
            reasoning = '\n'.join(lines[1:]).strip() if len(lines) > 1 else "Analysis complete"
            
            print(f"✓ AI Analysis Complete")
            print(f"  Score: {score}/100")
            print(f"  Reasoning: {reasoning[:100]}..." if len(reasoning) > 100 else f"  Reasoning: {reasoning}")
            
            return score
            
        except Exception as e:
            print(f"⚠ AI health score calculation failed: {e}")
            print(f"  → Switching to rule-based fallback scoring")
            return self._fallback_health_score_with_notice(analysis_data)

    def _format_analysis_data(self, analysis_data):
        """Format the analysis data into a clear, readable summary for the AI."""
        repo_data = analysis_data.get('repo_data', {})
        security = analysis_data.get('security_issues', {})
        dependencies = analysis_data.get('dependencies', {})
        ci_cd = analysis_data.get('ci_cd', {})
        docs = analysis_data.get('documentation', {})
        
        # Calculate days in human terms
        days_old = repo_data.get('days_since_activity', 0)
        if days_old == 0:
            age_str = "updated today"
        elif days_old == 1:
            age_str = "updated yesterday"
        elif days_old < 7:
            age_str = f"updated {days_old} days ago"
        elif days_old < 30:
            age_str = f"updated {days_old // 7} weeks ago"
        elif days_old < 365:
            age_str = f"updated {days_old // 30} months ago"
        else:
            years = days_old // 365
            age_str = f"updated {years} year{'s' if years > 1 else ''} ago"
        
        summary = f"""
REPOSITORY: {repo_data.get('name', 'Unknown')}
- Language: {repo_data.get('language', 'Unknown')}
- Stars: {repo_data.get('stars', 0):,}
- Forks: {repo_data.get('forks', 0):,}
- Open Issues: {repo_data.get('open_issues', 0)}
- Last Activity: {age_str}
- Archived: {'YES - No longer maintained' if repo_data.get('archived') else 'No'}
- License: {repo_data.get('license', 'None')}

SECURITY ANALYSIS:
- Critical Security Issues: {security.get('critical_issues', 0)}
- High Severity Issues: {security.get('high_issues', 0)}
- Medium Severity Issues: {security.get('medium_issues', 0)}
- Low Severity Issues: {security.get('low_issues', 0)}
- GitHub Security Advisories (GHSA): {len(security.get('ghsa_alerts', []))}
- Security Score: {security.get('security_score', 0)}/100
"""
        
        # Add GHSA details if present
        if security.get('ghsa_alerts'):
            summary += "\nGHSA Alert Details:\n"
            for alert in security.get('ghsa_alerts', [])[:3]:
                summary += f"  - {alert.get('severity', 'unknown').upper()}: {alert.get('summary', 'Security vulnerability')}\n"
            if len(security.get('ghsa_alerts', [])) > 3:
                summary += f"  - ...and {len(security.get('ghsa_alerts', [])) - 3} more alerts\n"
        
        # Add security issue details
        if security.get('issues_found'):
            summary += "\nSecurity Issues Found:\n"
            for issue in security.get('issues_found', [])[:5]:
                summary += f"  - [{issue.get('severity', 'unknown').upper()}] {issue.get('description', 'Issue detected')}\n"
            if len(security.get('issues_found', [])) > 5:
                summary += f"  - ...and {len(security.get('issues_found', [])) - 5} more issues\n"
        
        summary += f"""
DEPENDENCIES:
- Total Dependencies: {dependencies.get('total_dependencies', 'Unknown')}
- Outdated Packages: {dependencies.get('outdated_count', 0)}
- Vulnerable Packages: {dependencies.get('vulnerable_count', 0)}
- Last Dependency Update: {dependencies.get('last_update', 'Unknown')}
- Package Managers: {', '.join(dependencies.get('package_managers', ['None detected']))}
"""
        
        # Add vulnerable dependency details
        if dependencies.get('vulnerable_dependencies'):
            summary += "\nVulnerable Dependencies:\n"
            for dep in dependencies.get('vulnerable_dependencies', [])[:5]:
                summary += f"  - {dep.get('name')}: {dep.get('vulnerability', 'CVE')} (severity: {dep.get('severity', 'unknown')})\n"
            if len(dependencies.get('vulnerable_dependencies', [])) > 5:
                summary += f"  - ...and {len(dependencies.get('vulnerable_dependencies', [])) - 5} more\n"
        
        summary += f"""
CI/CD PIPELINE:
- Has CI/CD: {'Yes' if ci_cd.get('has_ci_cd') else 'No'}
- Pipeline Type: {ci_cd.get('pipeline_type', 'None')}
- Last Run Status: {ci_cd.get('last_run_status', 'Unknown')}
- Number of Workflows: {ci_cd.get('workflow_count', 0)}

DOCUMENTATION:
- README: {'Yes (' + str(docs.get('readme_size', 0)) + ' bytes)' if docs.get('has_readme') else 'No'}
- License File: {'Yes (' + docs.get('license_type', 'present') + ')' if docs.get('has_license') else 'No'}
- Contributing Guide: {'Yes' if docs.get('has_contributing') else 'No'}
- Security Policy: {'Yes' if docs.get('has_security_policy') else 'No'}
- Code of Conduct: {'Yes' if docs.get('has_code_of_conduct') else 'No'}
- Changelog: {'Yes' if docs.get('has_changelog') else 'No'}
- Documentation Score: {docs.get('documentation_score', 0)}/100
"""
        
        return summary

    def _fallback_health_score_with_notice(self, analysis_data):
        """Fallback scoring when AI is unavailable."""
        self.ai_available = False
        print("━" * 60)
        print("⚠ FALLBACK MODE ACTIVATED")
        print("  Gemini AI is not responding.")
        print("  Using rule-based scoring algorithm.")
        print("━" * 60)
        
        score = 100
        repo_data = analysis_data.get('repo_data', {})
        days_old = repo_data.get('days_since_activity', 0)
        security = analysis_data.get('security_issues', {})
        deps = analysis_data.get('dependencies', {})
        
        if repo_data.get('archived'):
            print("  Repository is archived → Max score: 20")
            return 20
        
        # Heavy penalties for security
        score -= security.get('critical_issues', 0) * 30
        score -= len(security.get('ghsa_alerts', [])) * 25
        score -= security.get('high_issues', 0) * 15
        
        # Age-based caps
        if days_old > 1095:
            score = min(score, 30)
        elif days_old > 730:
            score = min(score, 45)
        elif days_old > 365:
            score = min(score, 60)
        
        score -= deps.get('vulnerable_count', 0) * 10
        score -= min(20, deps.get('outdated_count', 0) // 2)
        
        final_score = max(0, min(100, score))
        print(f"  → Fallback score: {final_score}/100")
        print("━" * 60)
        return final_score
    
    def generate_insights(self, analysis_data):
        """Generate comprehensive AI-powered insights through actual analysis."""
        try:
            data_summary = self._format_analysis_data(analysis_data)
            
            prompt = f"""You are a senior technical consultant providing critical insights to a development team about a GitHub repository they're evaluating.

{data_summary}

Analyze this repository and provide 3-4 key insights that would help someone decide whether to:
- Use this repository in production
- Fork and maintain it themselves
- Look for alternatives

Your insights should be:
1. **Honest and direct** - don't sugarcoat issues
2. **Context-aware** - consider the repository's purpose, popularity, and domain
3. **Actionable** - include specific recommendations
4. **Prioritized** - start with the most critical finding

Think about:
- What's the biggest risk or opportunity here?
- Is this project alive and maintained, or is it abandoned?
- Are there security concerns that are dealbreakers?
- What would you tell your team if they asked "should we use this?"

Write 3-4 insights as clear paragraphs. Each insight should be 1-3 sentences. Be conversational but professional - like you're explaining this to a colleague."""

            response = self.model.generate_content(prompt)
            insights_text = response.text.strip()
            
            # Split into paragraphs
            paragraphs = [p.strip() for p in insights_text.split('\n\n') if p.strip()]
            
            # If no double newlines, try single newlines
            if len(paragraphs) < 2:
                paragraphs = [p.strip() for p in insights_text.split('\n') if p.strip()]
            
            # Clean up formatting
            insights = []
            for para in paragraphs:
                # Remove markdown
                para = re.sub(r'\*\*([^*]+)\*\*', r'\1', para)
                para = re.sub(r'\*([^*]+)\*', r'\1', para)
                para = re.sub(r'^[*\-•\d\.)\]]\s*', '', para)
                para = para.strip()
                
                if len(para) > 30 and not para.startswith('#'):
                    insights.append(para)
            
            if len(insights) < 2:
                print("⚠ AI insights insufficient, using fallback")
                return self._generate_fallback_insights(analysis_data)
            
            print(f"✓ AI generated {len(insights[:4])} insights")
            return insights[:4]
            
        except Exception as e:
            print(f"⚠ AI insights generation failed: {e}")
            print("  → Using fallback insights")
            return self._generate_fallback_insights(analysis_data)
    
    def _generate_fallback_insights(self, analysis_data):
        """Generate basic insights when AI fails."""
        self.ai_available = False
        print("⚠ Using fallback insights (AI unavailable)")
        
        insights = []
        repo_data = analysis_data.get('repo_data', {})
        security = analysis_data.get('security_issues', {})
        dependencies = analysis_data.get('dependencies', {})
        
        days_old = repo_data.get('days_since_activity', 0)
        stars = repo_data.get('stars', 0)
        
        # Security first
        critical_count = security.get('critical_issues', 0) + len(security.get('ghsa_alerts', []))
        if critical_count > 0:
            insights.append(f"Critical security risk detected: {critical_count} critical vulnerabilities require immediate attention before this repository can be safely used in production.")
        
        # Maintenance status
        if repo_data.get('archived'):
            insights.append("This repository is archived and no longer maintained. No security updates or bug fixes will be released. Consider finding an actively maintained alternative.")
        elif days_old > 730:
            insights.append(f"This repository hasn't been updated in {days_old // 365} years and appears abandoned. Using it would require taking on maintenance yourself or finding an alternative.")
        elif days_old < 90 and stars > 1000:
            insights.append(f"Active and popular project with recent updates and {stars:,} stars, indicating healthy community engagement and ongoing maintenance.")
        
        # Dependencies
        if dependencies.get('vulnerable_count', 0) > 0:
            insights.append(f"Found {dependencies.get('vulnerable_count')} vulnerable dependencies that need updating. These represent known security issues with available patches.")
        elif dependencies.get('outdated_count', 0) > 20:
            insights.append(f"Significant technical debt with {dependencies.get('outdated_count')} outdated dependencies requiring updates and testing before production use.")
        
        # Ensure we have at least 3 insights
        if len(insights) < 3:
            if days_old < 180:
                insights.append("Recent activity suggests ongoing maintenance. Recommend standard security audit and testing before production deployment.")
            else:
                insights.append("Limited recent activity detected. Comprehensive code review and security testing recommended before production use.")
        
        return insights[:4]
    
    def get_ai_status_message(self):
        """Return message about AI availability."""
        if not self.ai_available:
            return {
                'ai_used': False,
                'message': '⚠️ AI Analysis Unavailable',
                'description': 'Analysis provided using rule-based algorithms based on GitHub API data.',
                'recommendation': 'Check GOOGLE_API_KEY in .env file to enable AI-powered analysis.'
            }
        return {
            'ai_used': True,
            'message': '✓ AI-Powered Analysis',
            'description': 'Intelligent analysis by Google Gemini 2.5 Flash',
            'recommendation': ''
        }