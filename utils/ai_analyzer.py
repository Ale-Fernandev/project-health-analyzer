import google.generativeai as genai
import json

class AIAnalyzer:
    """AI-powered analyzer using Google's Gemini for intelligent scoring and insights."""
    
    def __init__(self, api_key):
        """Initialize with Google's Gemini API."""
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
    def calculate_health_score_ai(self, analysis_data):
        """Let AI determine the health score based on ALL data"""
        try:
            # Convert all data to a comprehensive summary
            
            data_summary = json.dumps(analysis_data, indent=2, default=str)
            # Prompt for Gemini to return a scor
            prompt = f"""
            You are an expert software engineer evaluating a Github repository's health.

            Analyze this complete repository data and return a health score from 0-100.

            DATA:
            
            {data_summary}

            SCORING CRITERIA:
            - 90-100: Excellent - Actively maintained, no security issues, production-ready
            - 70-89: Good - Well maintained, minor issues, safe to use
            - 50-69: Fair - Needs updates, some concerns, use with caution
            - 30-49: Poor - Significant issues, abandoned or vulnerable
            - 0-29: Critical - Severely compromised, abandoned, or dangerous

            Consider these factors:
            1. Security vulnerabilities (MOST IMPORTANT)
            - Known CVEs, GHSA alerts, exposed secrets
            2. Maintenance Status
            - When last updated vs. type of project
            - A stable library not updated for 2 years might be fine
            - A web framework not updated for 2 years is concerning
            3. Dependencies
            - Vulnerable dependencies are critical
            - Outdated dependencies are concering
            4. Project maturity
            - Documentation, CI/CD, license, etc...
            5. Context
            - 200,000 Stars means it's probably maintained even if CI/CD fails, but check regardless..
            - 0-10,000 Stars and 3 years old probably means its abandoned
            
            IMPORTANT CONTEXTUAL RULES:
            - Known projects by big companies with failing CI/CD but still recently updated should receive a good score
            - A project by an unknown person from 5 years ago shouldn't receive a high score, especially if there are many outdated dependencies
            - Popular library with no updates for over a year but has no vulnerabilities or out dated packages should receive a score above 60
            - Any project with critical vulnerabilities shouldn't receive a score higher than 40
            - Any project with exposed secrets shouldn't receive a score higher than 20

            Return ONLY a number between 0-100, nothing else.
            """
            
            response = self.model.generate_content(prompt)
            score_text = response.text.strip()
            
            # Extract just the number
            score = int(''.join(filter(str.isdigit, score_text)))
            score = max(0, min(100, score))
            
            print(f"AI calculated health score: {score}")
            return score
            
        except Exception as e:
            print(f"Error in AI health score calculation: {e}")
            return self._fallback_health_score_improved(analysis_data)

    def _fallback_health_score_improved(self, analysis_data):
        """Improved fallback scoring that's less harsh on CI/CD."""
        score = 100
        
        # Extract data
        days_old = analysis_data.get('repo_data', {}).get('days_since_activity', 0)
        stars = analysis_data.get('repo_data', {}).get('stars', 0)
        archived = analysis_data.get('repo_data', {}).get('archived', False)
        security = analysis_data.get('security_issues', {})
        deps = analysis_data.get('dependencies', {})
        ci_cd = analysis_data.get('ci_cd', {})
        docs = analysis_data.get('documentation', {})
        
        # Special handling for popular, active projects
        is_popular = stars > 10000
        is_very_popular = stars > 50000
        is_active = days_old < 30
        
        if archived:
            return 25
        
        # Age penalties (less harsh for popular projects)
        if days_old > 1095:  # 3+ years
            score = min(score, 30)
        elif days_old > 730:  # 2+ years
            score = min(score, 40)
        elif days_old > 365:  # 1+ year
            score = min(score, 60 if not is_popular else 70)
        elif days_old > 180:  # 6+ months
            score -= 10 if not is_popular else 5
        elif days_old > 90:  # 3+ months
            score -= 5 if not is_popular else 2
        
        # Security penalties
        score -= security.get('critical_issues', 0) * 20
        score -= security.get('high_issues', 0) * 10
        score -= security.get('medium_issues', 0) * 5
        score -= len(security.get('ghsa_alerts', [])) * 15
        
        # Dependency penalties (less harsh for active projects)
        outdated = deps.get('outdated_count', 0)
        if is_active:
            score -= min(15, outdated)  # Cap at -15 for active projects
        else:
            score -= min(30, outdated * 2)
        
        score -= deps.get('vulnerable_count', 0) * 10
        
        # CI/CD penalties (much less harsh)
        ci_status = ci_cd.get('last_run_status', 'Unknown')
        if not ci_cd.get('has_ci_cd', False):
            score -= 15
        elif ci_status == 'failure' and is_active:
            score -= 5  # Only -5 for active projects with failing CI/CD
        elif ci_status == 'failure':
            score -= 10
        elif ci_status in ['Unknown', 'Unable to Access (Exists)']:
            score -= 3  # Minimal penalty if we know CI/CD exists but can't access
        
        # Documentation
        if not docs.get('has_readme', False):
            score -= 10
        if not docs.get('has_license', False):
            score -= 5
        
        # Bonus for very popular projects
        if is_very_popular and is_active:
            score = max(score, 75)  # Minimum 75 for very popular, active projects
        elif is_popular and is_active:
            score = max(score, 65)  # Minimum 65 for popular, active projects
        
        return max(0, min(100, score))
    
    def generate_insights(self, analysis_data):
        """Generate comprehensive AI-powered insights."""
        try:
            data_summary = json.dumps(analysis_data, indent=2, default=str)
            
            prompt = f"""
            As a software security expert, analyze this repository data and provide exactly 4 insights.

            Data:
            {data_summary}

            Provide insights in this format:
            1. One insight about the maintenance/abandonment status, if any
            2. One insight about security vulnerabilities or risks, if any
            3. One insight about dependencies and technical debt, if any
            4. One recommendation for someone considering usingg this repository

            Each insight should be a single, clear sentence.
            Be specific - mention actual numbers, dates, and issues or vulnerabilities that were found.
            Be honest - if it's abandoned or bulnerable, say so clearly.

            Focus on what matters most for someone evaluating whether to use this code or not.
            """
            
            response = self.model.generate_content(prompt)
            insights_text = response.text
            
            # Parse insights
            insights = []
            for line in insights_text.split('\n'):
                line = line.strip()
                if line and len(line) > 20:
                    # Remove markdown formatting and numbering
                    line = line.lstrip('1234567890.-* ')
                    if line:
                        insights.append(line)
            
            return insights[:4]  # Return max 4 insights
            
        except Exception as e:
            print(f"Error generating AI insights: {e}")
            return [
                "Unable to generate AI insights at this time.",
                "Review the security and dependency information above",
                "Check the lat update date to assess maintenance status",
                "Consider the repository's age and activity level"
            ]
    def generate_verdict(self, analysis_data, health_score):
            """Generate a clear verdict about the repository."""
            try:
                data_summary = json.dumps(analysis_data, indent=2, default=str)
                
                prompt = f"""
                Based on this repository analysis with a health score of {health_score}/100:
                
                {data_summary}
                
                Provide a 2-3 sentence VERDICT that answers:
                1. Should someone use this repository? (Yes/No/With Caution)
                2. What's the main risk or benefit?
                3. What type of project is this suitable for? (Production/Development/Hobby/None)
                
                Be direct and clear. Examples:
                - "DO NOT USE. This repository has been abandoned for 5 years and contains multiple critical vulnerabilities."
                - "SAFE TO USE. Well-maintained project with regular updates and no security issues."
                - "USE WITH CAUTION. The code is stable but hasn't been updated in 2 years - review dependencies before production use."
                
                Start with: SAFE TO USE, USE WITH CAUTION, or DO NOT USE.
                """
                
                response = self.model.generate_content(prompt)
                return response.text.strip()
                
            except Exception as e:
                print(f"Error generating verdict: {e}")
                
                if health_score >= 70:
                    return "SAFE TO USE. This repository appears to be in good health with minimal issues."
                elif health_score >= 40:
                    return "USE WITH CAUTION. This repository has some issues that should be addressed before production use."
                else:
                    return "DO NOT USE. This repository has significant issues and should not be used without major updates."
    
    def analyze_specific_concerns(self, analysis_data):
        """Let AI identify specific concerns that might not be in our checks."""
        try:
            prompt = f"""
            As a security expert, review this repository data and identify any concerns 
            that might not be captured by standard metrics:
            
            Repository: {analysis_data.get('repo_data', {}).get('name')}
            Language: {analysis_data.get('repo_data', {}).get('language')}
            Last Updated: {analysis_data.get('repo_data', {}).get('days_since_activity')} days ago
            Stars: {analysis_data.get('repo_data', {}).get('stars')}
            
            Look for red flags like:
            - Language-specific vulnerabilities (e.g., old PHP, Python 2)
            - Deprecated technologies
            - Suspicious patterns
            - Maintenance concerns specific to this type of project
            
            Return 1-2 specific concerns if any, or "No additional concerns" if the standard metrics cover everything.
            Keep response under 50 words.
            """
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            print(f"Error analyzing specific concerns: {e}")
            return "Unable to analyze additional concerns."
