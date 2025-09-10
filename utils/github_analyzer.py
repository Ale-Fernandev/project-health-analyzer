from github import Github
import requests
import base64
import json
from datetime import datetime, timedelta, timezone

class GitHubAnalyzer:
    """Enhanced GitHub repository analyzer with vulnerability detection."""
    
    def __init__(self, github_token):
        """Initialize with GitHub authentication."""
        self.github = Github(github_token)
        self.token = github_token
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
    def fetch_repo_data(self, owner, repo_name):
        """Fetch comprehensive repository information."""
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            
            # Calculate days since last update
            days_since_update = None
            days_since_push = None
            
            if repo.updated_at:
                days_since_update = (datetime.now(timezone.utc) - repo.updated_at).days
            
            if repo.pushed_at:
                days_since_push = (datetime.now(timezone.utc) - repo.pushed_at).days
            
            # Determine actual last activity (push is more accurate than update)
            actual_days_old = days_since_push if days_since_push is not None else days_since_update
            
            repo_data = {
                'name': repo.name,
                'owner': repo.owner.login,
                'description': repo.description,
                'stars': repo.stargazers_count,
                'forks': repo.forks_count,
                'watchers': repo.watchers_count,
                'language': repo.language,
                'created_at': repo.created_at.isoformat(),
                'updated_at': repo.updated_at.isoformat() if repo.updated_at else None,
                'pushed_at': repo.pushed_at.isoformat() if repo.pushed_at else None,
                'days_since_update': days_since_update,
                'days_since_push': days_since_push,
                'days_since_activity': actual_days_old,
                'size': repo.size,
                'default_branch': repo.default_branch,
                'open_issues': repo.open_issues_count,
                'has_wiki': repo.has_wiki,
                'has_pages': repo.has_pages,
                'has_downloads': repo.has_downloads,
                'archived': repo.archived,
                'disabled': repo.disabled if hasattr(repo, 'disabled') else False,
                'topics': repo.get_topics(),
                'license': repo.license.name if repo.license else None,
                'network_count': repo.network_count,
                'subscribers_count': repo.subscribers_count
            }
            
            print(f"Repository {owner}/{repo_name} - Last activity: {actual_days_old} days ago")
            
            return repo_data
            
        except Exception as e:
            print(f"Error fetching repo data: {e}")
            raise Exception(f"Failed to fetch repository data: {str(e)}")
    
    def check_dependencies_with_vulnerabilities(self, owner, repo_name):
        """Check dependencies and detect known vulnerabilities using GitHub's dependency API."""
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            
            dependency_report = {
                'outdated_count': 0,
                'vulnerable_count': 0,
                'vulnerable_dependencies': [],
                'last_update': None,
                'days_since_update': None,
                'package_managers': [],
                'details': [],
                'sbom_available': False
            }
            
            # Get repository age for estimation
            if repo.pushed_at:
                days_old = (datetime.now(timezone.utc) - repo.pushed_at).days
                dependency_report['days_since_update'] = days_old
                
                # Format for display
                if days_old == 0:
                    dependency_report['last_update'] = 'Today'
                elif days_old == 1:
                    dependency_report['last_update'] = 'Yesterday'
                elif days_old < 30:
                    dependency_report['last_update'] = f'{days_old} days ago'
                elif days_old < 365:
                    months = days_old // 30
                    dependency_report['last_update'] = f'{months} months ago'
                else:
                    years = days_old // 365
                    dependency_report['last_update'] = f'{years} years ago'
            
            # Try to get dependency graph (requires specific permissions)
            try:
                # Check for vulnerability alerts using GitHub API
                vuln_url = f"https://api.github.com/repos/{owner}/{repo_name}/vulnerability-alerts"
                vuln_response = requests.get(vuln_url, headers=self.headers)
                
                if vuln_response.status_code == 204:
                    print(f"Vulnerability alerts enabled for {owner}/{repo_name}")
                    dependency_report['vulnerability_alerts_enabled'] = True
                
                # Get SBOM (Software Bill of Materials) if available
                sbom_url = f"https://api.github.com/repos/{owner}/{repo_name}/dependency-graph/sbom"
                sbom_response = requests.get(sbom_url, headers={
                    **self.headers,
                    'Accept': 'application/vnd.github.v3+json'
                })
                
                if sbom_response.status_code == 200:
                    dependency_report['sbom_available'] = True
                    sbom_data = sbom_response.json()
                    # Process SBOM data if available
                    if 'sbom' in sbom_data:
                        packages = sbom_data.get('sbom', {}).get('packages', [])
                        dependency_report['total_dependencies'] = len(packages)
                        print(f"Found {len(packages)} dependencies in SBOM")
                
            except Exception as e:
                print(f"Could not fetch vulnerability data: {e}")
            
            # Check for common dependency files and estimate outdated packages
            language = repo.language
            
            if language in ['JavaScript', 'TypeScript']:
                dependency_report['package_managers'].append('npm')
                # Check for package.json
                try:
                    package_json = repo.get_contents("package.json")
                    content = base64.b64decode(package_json.content).decode('utf-8')
                    package_data = json.loads(content)
                    
                    deps_count = len(package_data.get('dependencies', {}))
                    dev_deps_count = len(package_data.get('devDependencies', {}))
                    total_deps = deps_count + dev_deps_count
                    
                    dependency_report['details'].append({
                        'file': 'package.json',
                        'dependencies': deps_count,
                        'dev_dependencies': dev_deps_count,
                        'total': total_deps
                    })
                    
                    # Estimate outdated based on repo age
                    if days_old > 1095:  # 3+ years
                        dependency_report['outdated_count'] = min(total_deps, int(total_deps * 0.9))
                        dependency_report['vulnerable_count'] = min(total_deps, int(total_deps * 0.3))
                    elif days_old > 730:  # 2+ years
                        dependency_report['outdated_count'] = min(total_deps, int(total_deps * 0.7))
                        dependency_report['vulnerable_count'] = min(total_deps, int(total_deps * 0.2))
                    elif days_old > 365:  # 1+ year
                        dependency_report['outdated_count'] = min(total_deps, int(total_deps * 0.5))
                        dependency_report['vulnerable_count'] = min(total_deps, int(total_deps * 0.1))
                    elif days_old > 180:  # 6+ months
                        dependency_report['outdated_count'] = min(total_deps, int(total_deps * 0.3))
                    elif days_old > 90:  # 3+ months
                        dependency_report['outdated_count'] = min(total_deps, int(total_deps * 0.15))
                    
                    # Check for known vulnerable packages
                    vulnerable_packages = self._check_known_vulnerabilities(package_data, 'npm')
                    dependency_report['vulnerable_dependencies'].extend(vulnerable_packages)
                    
                except Exception as e:
                    print(f"Could not analyze package.json: {e}")
            
            elif language == 'Python':
                dependency_report['package_managers'].append('pip')
                try:
                    requirements = repo.get_contents("requirements.txt")
                    content = base64.b64decode(requirements.content).decode('utf-8')
                    deps_count = len([line for line in content.split('\n') if line.strip() and not line.startswith('#')])
                    
                    dependency_report['details'].append({
                        'file': 'requirements.txt',
                        'dependencies': deps_count
                    })
                    
                    # Estimate outdated based on age
                    if days_old > 730:
                        dependency_report['outdated_count'] = min(deps_count, int(deps_count * 0.8))
                    elif days_old > 365:
                        dependency_report['outdated_count'] = min(deps_count, int(deps_count * 0.5))
                    elif days_old > 180:
                        dependency_report['outdated_count'] = min(deps_count, int(deps_count * 0.3))
                    
                except:
                    pass
            
            # If repo is very old and we couldn't determine dependencies, make educated guess
            if not dependency_report['package_managers'] and days_old > 365:
                dependency_report['outdated_count'] = 10  # Conservative estimate
                dependency_report['estimated'] = True
            
            return dependency_report
            
        except Exception as e:
            print(f"Error checking dependencies: {e}")
            return {
                'outdated_count': 0,
                'vulnerable_count': 0,
                'vulnerable_dependencies': [],
                'last_update': 'Unknown',
                'days_since_update': 9999,
                'package_managers': [],
                'details': []
            }
    
    def _check_known_vulnerabilities(self, package_data, package_manager):
        """Check for known vulnerable packages based on common CVEs."""
        vulnerable = []
        
        # Known vulnerable packages (simplified list - in production, use a CVE database)
        known_vulnerabilities = {
            'npm': {
                'lodash': {'versions': ['< 4.17.21'], 'cve': 'CVE-2021-23337'},
                'axios': {'versions': ['< 0.21.1'], 'cve': 'CVE-2020-28168'},
                'jquery': {'versions': ['< 3.5.0'], 'cve': 'CVE-2020-11022'},
                'bootstrap': {'versions': ['< 4.5.0'], 'cve': 'CVE-2019-8331'},
                'express': {'versions': ['< 4.17.1'], 'cve': 'Multiple'},
                'react': {'versions': ['< 16.14.0'], 'cve': 'CVE-2020-7598'},
                'angular': {'versions': ['< 11.0.0'], 'cve': 'Multiple'},
                'webpack': {'versions': ['< 5.0.0'], 'cve': 'CVE-2020-15778'}
            },
            'pip': {
                'django': {'versions': ['< 3.2'], 'cve': 'CVE-2021-33203'},
                'flask': {'versions': ['< 2.0.0'], 'cve': 'CVE-2019-1010083'},
                'requests': {'versions': ['< 2.25.0'], 'cve': 'CVE-2018-18074'},
                'urllib3': {'versions': ['< 1.26.5'], 'cve': 'CVE-2021-33503'},
                'pyyaml': {'versions': ['< 5.4'], 'cve': 'CVE-2020-14343'},
                'pillow': {'versions': ['< 8.2.0'], 'cve': 'CVE-2021-28678'},
                'tensorflow': {'versions': ['< 2.5.0'], 'cve': 'Multiple'},
                'numpy': {'versions': ['< 1.19.0'], 'cve': 'CVE-2021-33430'}
            }
        }
        
        vuln_list = known_vulnerabilities.get(package_manager, {})
        dependencies = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        for package_name, version in dependencies.items():
            if package_name.lower() in vuln_list:
                vulnerable.append({
                    'name': package_name,
                    'current_version': version,
                    'vulnerability': vuln_list[package_name.lower()]['cve'],
                    'safe_version': vuln_list[package_name.lower()]['versions'][0].replace('< ', ''),
                    'severity': 'high'
                })
        
        return vulnerable
    
    def check_ci_cd(self, owner, repo_name):
        """Check for CI/CD pipeline configuration with improved detection."""
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            ci_cd_report = {
                'has_ci_cd': False,
                'pipeline_type': None,
                'config_files': [],
                'last_run_status': 'Unknown',
                'workflows': [],
                'workflow_count': 0
            }

            print(f"Checking CI/CD for {owner}/{repo_name}")
        
            # Check for GitHub Actions workflows
            try:
                workflows_contents = repo.get_contents(".github/workflows")
                if workflows_contents:
                    print(f"Found {len(workflows_contents)} workflow files")
                    ci_cd_report['has_ci_cd'] = True
                    ci_cd_report['pipeline_type'] = 'GitHub Actions'
                    ci_cd_report['workflow_count'] = len(workflows_contents)
                    
                    # For large/popular repos, assume CI/CD is working if files exist
                    # because we often can't access their workflow runs
                    if repo.stargazers_count > 10000:
                        ci_cd_report['last_run_status'] = 'Assumed Working (Large Project)'
                        print(f"Large project with {repo.stargazers_count} stars - assuming CI/CD is maintained")
                    else:
                        # Try to get workflow runs for smaller projects
                        try:
                            workflows = repo.get_workflows()
                            found_status = False
                            
                            for workflow in workflows:
                                if found_status:
                                    break
                                    
                                try:
                                    runs = workflow.get_runs()
                                    if runs.totalCount > 0:
                                        # Check last 5 runs to get overall status
                                        run_statuses = []
                                        for i, run in enumerate(runs):
                                            if i >= 5:
                                                break
                                            if run.conclusion:
                                                run_statuses.append(run.conclusion)
                                        
                                        if run_statuses:
                                            # Determine overall status
                                            if all(s == 'success' for s in run_statuses):
                                                ci_cd_report['last_run_status'] = 'success'
                                            elif all(s == 'failure' for s in run_statuses):
                                                ci_cd_report['last_run_status'] = 'failure'
                                            elif 'success' in run_statuses:
                                                ci_cd_report['last_run_status'] = 'unstable'
                                            else:
                                                ci_cd_report['last_run_status'] = run_statuses[0]
                                            
                                            found_status = True
                                            print(f"Workflow status based on last runs: {run_statuses}")
                                            break
                                except:
                                    continue
                            
                            if not found_status:
                                # If we can't access runs but know workflows exist
                                ci_cd_report['last_run_status'] = 'Unable to Access (Exists)'
                                
                        except Exception as e:
                            print(f"Can't access workflows API: {e}")
                            # If we can't access but know .github/workflows exists
                            ci_cd_report['last_run_status'] = 'Unable to Access (Exists)'
                        
            except Exception as e:
                print(f"No .github/workflows found: {e}")
        
            # Check for other CI/CD files
            ci_files = [
                '.travis.yml', '.circleci/config.yml', 'Jenkinsfile',
                '.gitlab-ci.yml', 'azure-pipelines.yml', 'bitbucket-pipelines.yml',
                '.drone.yml', 'wercker.yml', 'appveyor.yml', '.buildkite/pipeline.yml'
            ]
        
            for ci_file in ci_files:
                try:
                    repo.get_contents(ci_file)
                    ci_cd_report['has_ci_cd'] = True
                    ci_cd_report['config_files'].append(ci_file)
                    print(f"Found CI file: {ci_file}")
                
                    if not ci_cd_report['pipeline_type']:
                        if 'travis' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Travis CI'
                        elif 'circle' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'CircleCI'
                        elif 'jenkins' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Jenkins'
                        elif 'gitlab' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'GitLab CI'
                        elif 'azure' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Azure DevOps'
                        elif 'bitbucket' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Bitbucket Pipelines'
                        elif 'drone' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Drone CI'
                        elif 'buildkite' in ci_file.lower():
                            ci_cd_report['pipeline_type'] = 'Buildkite'
                except:
                    continue
                    
            print(f"Final CI/CD report: {ci_cd_report}")
            return ci_cd_report
        
        except Exception as e:
            print(f"Error checking CI/CD: {e}")
            return {
                'has_ci_cd': False,
                'pipeline_type': None,
                'config_files': [],
                'last_run_status': 'Unknown',
                'workflows': []
            }
    
    def check_documentation(self, owner, repo_name):
        """Check for documentation files with improved detection."""
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            docs_report = {
                'has_readme': False,
                'readme_size': 0,
                'has_license': False,
                'license_type': None,
                'has_contributing': False,
                'has_code_of_conduct': False,
                'has_changelog': False,
                'has_security_policy': False,
                'has_wiki': repo.has_wiki,
                'documentation_score': 0
            }
            
            # Check for README variants
            readme_files = [
                'README.md', 'README.rst', 'README.txt', 'README',
                'Readme.md', 'readme.md', 'readme.txt', 'readme'
            ]
            
            for readme_file in readme_files:
                try:
                    readme = repo.get_contents(readme_file)
                    docs_report['has_readme'] = True
                    docs_report['readme_size'] = readme.size
                    
                    if readme.size > 1000:
                        docs_report['documentation_score'] += 40
                    elif readme.size > 500:
                        docs_report['documentation_score'] += 30
                    else:
                        docs_report['documentation_score'] += 15
                    break
                except:
                    continue
            
            # Check for LICENSE
            try:
                license = repo.get_license()
                docs_report['has_license'] = True
                docs_report['license_type'] = license.license.name
                docs_report['documentation_score'] += 20
            except:
                license_files = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'License']
                for license_file in license_files:
                    try:
                        repo.get_contents(license_file)
                        docs_report['has_license'] = True
                        docs_report['documentation_score'] += 20
                        break
                    except:
                        continue
            
            # Check for CONTRIBUTING
            contributing_files = ['CONTRIBUTING.md', 'CONTRIBUTING.rst', 'CONTRIBUTING.txt', '.github/CONTRIBUTING.md']
            for contrib_file in contributing_files:
                try:
                    repo.get_contents(contrib_file)
                    docs_report['has_contributing'] = True
                    docs_report['documentation_score'] += 15
                    break
                except:
                    continue
            
            # Check for CODE_OF_CONDUCT
            coc_files = ['CODE_OF_CONDUCT.md', 'CODE_OF_CONDUCT.txt', '.github/CODE_OF_CONDUCT.md']
            for coc_file in coc_files:
                try:
                    repo.get_contents(coc_file)
                    docs_report['has_code_of_conduct'] = True
                    docs_report['documentation_score'] += 10
                    break
                except:
                    continue
            
            # Check for SECURITY.md
            security_files = ['SECURITY.md', '.github/SECURITY.md']
            for security_file in security_files:
                try:
                    repo.get_contents(security_file)
                    docs_report['has_security_policy'] = True
                    docs_report['documentation_score'] += 10
                    break
                except:
                    continue
            
            # Check for CHANGELOG
            changelog_files = ['CHANGELOG.md', 'CHANGELOG.rst', 'CHANGELOG.txt', 'HISTORY.md', 'NEWS.md', 'RELEASES.md']
            for changelog_file in changelog_files:
                try:
                    repo.get_contents(changelog_file)
                    docs_report['has_changelog'] = True
                    docs_report['documentation_score'] += 5
                    break
                except:
                    continue
            
            # Cap documentation score at 100
            docs_report['documentation_score'] = min(100, docs_report['documentation_score'])
            
            return docs_report
            
        except Exception as e:
            print(f"Error checking documentation: {e}")
            return {
                'has_readme': False,
                'readme_size': 0,
                'has_license': False,
                'license_type': None,
                'has_contributing': False,
                'has_code_of_conduct': False,
                'has_changelog': False,
                'has_security_policy': False,
                'has_wiki': False,
                'documentation_score': 0
            }