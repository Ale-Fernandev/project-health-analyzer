import google.generativeai as genai
import json

class AIAnalyzer:
    """AI-powered analyzer using Google's Gemini for intelligent scoring and insights."""
    
    def __init__(self, api_key):
        """Initialize with Google's Gemini API."""
        genai.configure(api_key=api_key)
        # Use the latest Gemini model
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        
    def calculate_health_score_ai(self, analysis_data):
        """Use AI to calculate a more nuanced health score based on all factors."""
        try:
            # Extract key metrics
            days_old = analysis_data.get('repo_data', {}).get('days_since_activity', 9999)
            stars = analysis_data.get('repo_data', {}).get('stars', 0)
            
            prompt = f"""
            As an expert software engineer, calculate a health score (0-100) for this repository.
            
            CONTEXT:
            - Repository: {analysis_data.get('repo_data', {}).get('name', 'Unknown')}
            - Stars: {stars}
            - Days since last update: {days_old} days
            - Archived: {analysis_data.get('repo_data', {}).get('archived', False)}
            
            CRITICAL FACTORS:
            - Critical security issues: {analysis_data.get('security_issues', {}).get('critical_issues', 0)}
            - GHSA alerts: {len(analysis_data.get('security_issues', {}).get('ghsa_alerts', []))}
            - Days since update: {days_old}
            
            HIGH IMPORTANCE:
            - High security issues: {analysis_data.get('security_issues', {}).get('high_issues', 0)}
            - Vulnerable dependencies: {analysis_data.get('dependencies', {}).get('vulnerable_count', 0)}
            - Outdated dependencies: {analysis_data.get('dependencies', {}).get('outdated_count', 0)}
            
            MODERATE IMPORTANCE:
            - CI/CD exists: {analysis_data.get('ci_cd', {}).get('has_ci_cd', False)}
            - CI/CD status: {analysis_data.get('ci_cd', {}).get('last_run_status', 'Unknown')}
            - Medium security issues: {analysis_data.get('security_issues', {}).get('medium_issues', 0)}
            - Documentation: README={analysis_data.get('documentation', {}).get('has_readme', False)}, License={analysis_data.get('documentation', {}).get('has_license', False)}
            
            SCORING RULES:
            1. If repository has >10,000 stars and updated within 30 days, minimum score is 65 (popular and active)
            2. If repository has >50,000 stars and updated within 90 days, minimum score is 75 (very popular)
            3. CI/CD "failure" in active repos (updated <30 days) should only deduct 5-10 points, not 20+
            4. CI/CD "Unknown" or "Unable to Access" should only deduct 5 points if repo is otherwise healthy
            5. For repos not updated in 2+ years, maximum score is 40
            6. For repos not updated in 1+ year, maximum score is 60
            7. Archived repos get maximum 25
            
            IMPORTANT: Popular, actively maintained projects (like React with 200k+ stars, updated recently) 
            should score 75-95 even with CI/CD issues. A failing CI/CD in an active project is much less 
            concerning than an abandoned project.
            
            Return ONLY a number between 0-100.
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
            repo_data = analysis_data.get('repo_data', {})
            security = analysis_data.get('security_issues', {})
            dependencies = analysis_data.get('dependencies', {})
            ci_cd = analysis_data.get('ci_cd', {})
            docs = analysis_data.get('documentation', {})
            
            prompt = f"""
            Analyze this GitHub repository and provide 3-4 concise, actionable insights.
            
            Repository: {repo_data.get('name', 'Unknown')}
            Language: {repo_data.get('language', 'Unknown')}
            Last updated: {repo_data.get('days_since_activity', 'Unknown')} days ago
            Stars: {repo_data.get('stars', 0)}
            Open issues: {repo_data.get('open_issues', 0)}
            Archived: {repo_data.get('archived', False)}
            
            Security:
            - Critical issues: {security.get('critical_issues', 0)}
            - High issues: {security.get('high_issues', 0)}
            - GHSA alerts: {len(security.get('ghsa_alerts', []))}
            - Security score: {security.get('security_score', 0)}/100
            
            Dependencies:
            - Outdated: {dependencies.get('outdated_count', 0)}
            - Vulnerable: {dependencies.get('vulnerable_count', 0)}
            - Last update: {dependencies.get('last_update', 'Unknown')}
            
            CI/CD:
            - Has CI/CD: {ci_cd.get('has_ci_cd', False)}
            - Type: {ci_cd.get('pipeline_type', 'None')}
            - Status: {ci_cd.get('last_run_status', 'Unknown')}
            
            Documentation:
            - README: {docs.get('has_readme', False)} ({docs.get('readme_size', 0)} bytes)
            - License: {docs.get('has_license', False)}
            - Security policy: {docs.get('has_security_policy', False)}
            
            Provide insights focusing on:
            1. The most critical issue that needs immediate attention
            2. The repository's maintenance status and viability
            3. Security posture and risks
            4. Specific, actionable next steps
            
            Be direct and specific. Each insight should be 1-2 sentences maximum.
            Focus on what matters most for someone evaluating this repository.
            """
            
            response = self.model.generate_content(prompt)
            insights_text = response.text
            
            # Parse insights into list
            insights = []
            for line in insights_text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Remove markdown formatting and numbering
                    line = line.lstrip('*-•123456789. ')
                    if len(line) > 20:
                        insights.append(line)
            
            # Ensure we have at least some insights
            if not insights:
                insights = self._generate_fallback_insights(analysis_data)
            
            return insights[:4]  # Return max 4 insights
            
        except Exception as e:
            print(f"Error generating AI insights: {e}")
            return self._generate_fallback_insights(analysis_data)
    
    def _generate_fallback_insights(self, analysis_data):
        """Generate fallback insights if AI fails."""
        insights = []
        
        repo_data = analysis_data.get('repo_data', {})
        security = analysis_data.get('security_issues', {})
        dependencies = analysis_data.get('dependencies', {})
        ci_cd = analysis_data.get('ci_cd', {})
        
        days_old = repo_data.get('days_since_activity', 0)
        
        # Maintenance status
        if days_old > 730:
            insights.append(f"This repository hasn't been updated in {days_old // 365} years and appears to be abandoned. Consider finding an actively maintained alternative.")
        elif days_old > 365:
            insights.append(f"With no updates in {days_old // 30} months, this repository is becoming stale and may have unpatched vulnerabilities.")
        
        # Security status
        total_security_issues = (
            security.get('critical_issues', 0) + 
            security.get('high_issues', 0) + 
            len(security.get('ghsa_alerts', []))
        )
        if total_security_issues > 0:
            insights.append(f"Critical security concern: {total_security_issues} high-priority security issues need immediate attention.")
        
        # Dependencies
        outdated = dependencies.get('outdated_count', 0)
        if outdated > 10:
            insights.append(f"With {outdated} outdated dependencies, this project has significant technical debt that will require substantial effort to modernize.")
        
        # CI/CD
        if not ci_cd.get('has_ci_cd', False):
            insights.append("No CI/CD pipeline detected, indicating lack of automated quality assurance and modern development practices.")
        elif ci_cd.get('last_run_status') == 'failure':
            insights.append("The CI/CD pipeline is failing, suggesting the codebase may have breaking changes or test failures.")
        
        # Overall recommendation
        if days_old > 730 or total_security_issues > 5:
            insights.append("High risk: This repository requires major renovation or replacement before production use.")
        elif days_old > 365 or total_security_issues > 2:
            insights.append("Medium risk: Significant updates and security patches needed before this repository is production-ready.")
        else:
            insights.append("Low risk: This repository appears to be in reasonable health but should still undergo security review.")
        
        return insights[:4]
    
    def analyze_code_quality(self, repo_data):
        """Analyze code quality indicators using AI."""
        try:
            prompt = f"""
            Based on these repository metrics, assess the code quality and maintainability:
            
            - Language: {repo_data.get('language', 'Unknown')}
            - Size: {repo_data.get('size', 0)} KB
            - Open issues: {repo_data.get('open_issues', 0)}
            - Forks: {repo_data.get('forks', 0)}
            - Stars: {repo_data.get('stars', 0)}
            - Contributors: {repo_data.get('contributors_count', 'Unknown')}
            - Last update: {repo_data.get('days_since_activity', 'Unknown')} days ago
            
            Provide a brief assessment of:
            1. Likely code maintainability
            2. Community engagement level
            3. Technical debt indicators
            
            Keep response under 100 words and be specific.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            print(f"Error analyzing code quality: {e}")
            return "Code quality analysis requires manual review."
    
    def generate_business_recommendation(self, analysis_data, health_score):
        """Generate business-focused recommendations for decision makers."""
        try:
            prompt = f"""
            As a technical consultant, provide a business recommendation for this repository:
            
            Health Score: {health_score}/100
            Days since update: {analysis_data.get('repo_data', {}).get('days_since_activity', 'Unknown')}
            Security issues: {analysis_data.get('security_issues', {}).get('critical_issues', 0)} critical, {analysis_data.get('security_issues', {}).get('high_issues', 0)} high
            Outdated dependencies: {analysis_data.get('dependencies', {}).get('outdated_count', 0)}
            Stars: {analysis_data.get('repo_data', {}).get('stars', 0)}
            
            Provide a 2-3 sentence executive summary addressing:
            1. Should a company adopt/build upon this repository?
            2. Estimated effort level (low/medium/high) to make it production-ready
            3. Main risk factor
            
            Be direct and business-focused. No technical jargon.
            """
            
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            print(f"Error generating business recommendation: {e}")
            
            # Fallback business recommendation
            if health_score >= 70:
                return "This repository is in good health and suitable for adoption with minimal updates required. Low effort needed to deploy to production. Main risk: Ensure security patches are current."
            elif health_score >= 40:
                return "This repository requires moderate renovation before production use. Medium effort needed including dependency updates and security fixes. Main risk: Technical debt from outdated components."
            else:
                return "This repository is high-risk and not recommended for adoption without major overhaul. High effort required for modernization. Main risk: Abandoned codebase with unpatched vulnerabilities."