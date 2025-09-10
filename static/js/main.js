document.addEventListener('DOMContentLoaded', function() {
    console.log('JavaScript loaded!');
    
    // Get references to important elements
    const repoInput = document.getElementById('repo-url');
    const analyzeBtn = document.getElementById('analyze-btn');
    const progressSection = document.getElementById('progress-section');
    const resultsSection = document.getElementById('results-section');
    const errorSection = document.getElementById('error-section');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const newAnalysisBtn = document.getElementById('new-analysis-btn');
    const retryBtn = document.getElementById('retry-btn');
    const downloadReportBtn = document.getElementById('download-report-btn');
    
    // Store the current analysis data
    let currentAnalysis = null;
    let analysisStartTime = null;
    
    // Add event listeners
    analyzeBtn.addEventListener('click', startAnalysis);
    newAnalysisBtn.addEventListener('click', resetAnalysis);
    retryBtn.addEventListener('click', resetAnalysis);
    downloadReportBtn.addEventListener('click', downloadReport);
    
    // Allow Enter key to trigger analysis
    repoInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startAnalysis();
        }
    });
    
    // Main analysis function
    async function startAnalysis() {
        // Clear previous results first
        clearPreviousResults();
        
        // Get the repository URL
        const repoUrl = repoInput.value.trim();
        
        // Validate the URL
        if (!repoUrl) {
            showError('Please enter a GitHub repository URL');
            return;
        }
        
        // Basic GitHub URL validation
        const githubRegex = /^https:\/\/github\.com\/[\w-]+\/[\w-]+/;
        if (!githubRegex.test(repoUrl)) {
            showError('Please enter a valid GitHub repository URL (e.g., https://github.com/username/repository)');
            return;
        }
        
        // Hide any previous results or errors
        resultsSection.style.display = 'none';
        errorSection.style.display = 'none';
        
        // Show progress section
        progressSection.style.display = 'block';
        
        // Disable the analyze button
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
        
        // Start timer
        analysisStartTime = Date.now();
        
        // Start the progress animation
        animateProgress();
        
        try {
            // Make the API call to analyze the repository
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ repo_url: repoUrl })
            });
            
            // Parse the response
            const data = await response.json();
            
            if (data.success) {
                // Store the analysis data
                currentAnalysis = data;
                
                // Display the results
                displayResults(data);
            } else {
                throw new Error(data.error || 'Analysis failed');
            }
            
        } catch (error) {
            console.error('Analysis error:', error);
            showError(error.message || 'Failed to analyze repository. Please try again.');
        } finally {
            // Re-enable the analyze button
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = '<i class="fas fa-microscope"></i> Analyze';
            
            // Hide progress section
            progressSection.style.display = 'none';
        }
    }
    
    // Clear previous results
    function clearPreviousResults() {
        // Clear all result sections
        resultsSection.style.display = 'none';
        document.getElementById('score-value').textContent = '0';
        document.getElementById('score-fill').style.strokeDashoffset = '565';
        document.getElementById('security-content').innerHTML = '';
        document.getElementById('dependencies-content').innerHTML = '';
        document.getElementById('cicd-content').innerHTML = '';
        document.getElementById('docs-content').innerHTML = '';
        document.getElementById('ai-insights').style.display = 'none';
        document.getElementById('ai-content').innerHTML = '';
        document.getElementById('recommendations').style.display = 'none';
        document.getElementById('recommendations-list').innerHTML = '';
        document.getElementById('repo-info').innerHTML = '';
        
        // Reset progress bar
        progressBar.style.width = '0%';
        progressText.textContent = 'Initializing analysis...';
        
        // Reset progress steps
        ['step-1', 'step-2', 'step-3', 'step-4'].forEach(step => {
            document.getElementById(step).classList.remove('active', 'completed');
        });
    }
    
    // Animate the progress bar with timer
    function animateProgress() {
        let progress = 0;
        const steps = ['step-1', 'step-2', 'step-3', 'step-4'];
        const messages = [
            'Fetching repository data...',
            'Scanning for security issues and GHSA alerts...',
            'Analyzing dependencies and vulnerabilities...',
            'Generating AI-powered insights...'
        ];
        
        const interval = setInterval(() => {
            progress += 10;
            progressBar.style.width = Math.min(progress, 90) + '%';
            
            // Update elapsed time
            if (analysisStartTime) {
                const elapsed = Math.floor((Date.now() - analysisStartTime) / 1000);
                const currentMessage = messages[Math.min(Math.floor(progress / 25), 3)];
                progressText.textContent = `${currentMessage} (${elapsed}s)`;
            }
            
            // Update progress steps
            const stepIndex = Math.floor((progress - 1) / 25);
            if (stepIndex < steps.length) {
                steps.forEach((step, index) => {
                    const stepElement = document.getElementById(step);
                    if (index < stepIndex) {
                        stepElement.classList.add('completed');
                        stepElement.classList.remove('active');
                    } else if (index === stepIndex) {
                        stepElement.classList.add('active');
                        stepElement.classList.remove('completed');
                    } else {
                        stepElement.classList.remove('active', 'completed');
                    }
                });
            }
            
            if (progress >= 100) {
                clearInterval(interval);
                progressBar.style.width = '100%';
                progressText.textContent = 'Analysis complete!';
                steps.forEach(step => {
                    document.getElementById(step).classList.add('completed');
                    document.getElementById(step).classList.remove('active');
                });
            }
        }, 800);
        
        // Stop the interval after 30 seconds max
        setTimeout(() => clearInterval(interval), 30000);
    }
    
    // Display analysis results
    function displayResults(data) {
        console.log('Displaying results:', data);
        
        // Show results section
        resultsSection.style.display = 'block';
        
        // Update health score
        displayHealthScore(data.health_score);
        
        // Update repository info
        displayRepoInfo(data.repository);
        
        // Update issue cards
        displaySecurityIssues(data.issues.security);
        displayDependencies(data.issues.dependencies);
        displayCICD(data.issues.ci_cd);
        displayDocumentation(data.issues.documentation);
        
        // Display AI insights if available
        if (data.ai_insights && data.ai_insights.length > 0) {
            displayAIInsights(data.ai_insights);
        }
        
        // Display recommendations
        if (data.recommendations && data.recommendations.length > 0) {
            displayRecommendations(data.recommendations);
        }
        
        // Smooth scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    // Display health score with animation
    function displayHealthScore(score) {
        const scoreValue = document.getElementById('score-value');
        const scoreFill = document.getElementById('score-fill');
        const scoreDetails = document.getElementById('score-details');
        
        // Animate the score number
        let currentScore = 0;
        const increment = score / 50;
        const timer = setInterval(() => {
            currentScore += increment;
            if (currentScore >= score) {
                currentScore = score;
                clearInterval(timer);
            }
            scoreValue.textContent = Math.round(currentScore);
        }, 20);
        
        // Animate the circle
        const circumference = 2 * Math.PI * 90;
        const offset = circumference - (score / 100) * circumference;
        scoreFill.style.strokeDashoffset = offset;
        
        // Change color based on score
        if (score >= 70) {
            scoreFill.style.stroke = 'var(--success-color)';
            scoreValue.style.color = 'var(--success-color)';
        } else if (score >= 40) {
            scoreFill.style.stroke = 'var(--warning-color)';
            scoreValue.style.color = 'var(--warning-color)';
        } else {
            scoreFill.style.stroke = 'var(--danger-color)';
            scoreValue.style.color = 'var(--danger-color)';
        }
        
        // Add score interpretation
        let interpretation = '';
        if (score >= 70) {
            interpretation = '<p><strong>Good Health!</strong> This repository is well-maintained and suitable for use.</p>';
        } else if (score >= 40) {
            interpretation = '<p><strong>Fair Health.</strong> This repository needs some updates and improvements.</p>';
        } else if (score >= 20) {
            interpretation = '<p><strong>Poor Health.</strong> Significant issues detected. Major work required.</p>';
        } else {
            interpretation = '<p><strong>Critical Condition!</strong> This repository has serious issues and may be abandoned.</p>';
        }
        scoreDetails.innerHTML = interpretation;
    }
    
    // Display repository information
    function displayRepoInfo(repo) {
        const repoInfoDiv = document.getElementById('repo-info');
        
        // Format last updated text
        let lastUpdatedText = repo.last_updated;
        if (repo.days_since_update !== undefined && repo.days_since_update !== 'Unknown') {
            const days = parseInt(repo.days_since_update);
            if (days > 365) {
                lastUpdatedText = `${Math.floor(days/365)} years ago`;
            } else if (days > 30) {
                lastUpdatedText = `${Math.floor(days/30)} months ago`;
            } else {
                lastUpdatedText = `${days} days ago`;
            }
        }
        
        repoInfoDiv.innerHTML = `
            <div class="repo-info-item">
                <i class="fab fa-github"></i>
                <span><strong>${repo.owner}/${repo.name}</strong></span>
            </div>
            <div class="repo-info-item">
                <i class="fas fa-star"></i>
                <span>${repo.stars.toLocaleString()} stars</span>
            </div>
            <div class="repo-info-item">
                <i class="fas fa-code"></i>
                <span>${repo.language || 'Unknown'}</span>
            </div>
            <div class="repo-info-item">
                <i class="fas fa-clock"></i>
                <span>Updated ${lastUpdatedText}</span>
            </div>
        `;
    }
    
    // Display security issues with details
    function displaySecurityIssues(security) {
        const securityContent = document.getElementById('security-content');
        const critical = security.critical_issues || 0;
        const high = security.high_issues || 0;
        const medium = security.medium_issues || 0;
        const low = security.low_issues || 0;
        const ghsaAlerts = security.ghsa_alerts || [];
        
        let html = `
            <div class="issue-stat">
                <span class="issue-stat-label">Critical Issues:</span>
                <span class="issue-stat-value ${critical > 0 ? 'critical' : 'success'}">${critical}</span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">High Priority:</span>
                <span class="issue-stat-value ${high > 0 ? 'warning' : 'success'}">${high}</span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Medium Priority:</span>
                <span class="issue-stat-value ${medium > 0 ? 'warning' : ''}">${medium}</span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Low Priority:</span>
                <span class="issue-stat-value">${low}</span>
            </div>
        `;
        
        // Add GHSA alerts if present
        if (ghsaAlerts.length > 0) {
            html += `
                <div class="issue-stat">
                    <span class="issue-stat-label">GHSA Alerts:</span>
                    <span class="issue-stat-value critical">${ghsaAlerts.length}</span>
                </div>
            `;
        }
        
        // Add detailed issues if available
        if (security.issues_found && security.issues_found.length > 0) {
            html += '<div style="margin-top: 10px; font-size: 0.85em;">';
            html += '<strong>Details:</strong><ul style="margin: 5px 0; padding-left: 20px;">';
            
            // Show first 3 issues
            security.issues_found.slice(0, 3).forEach(issue => {
                const severityColor = issue.severity === 'critical' ? 'color: var(--danger-color)' : 
                                     issue.severity === 'high' ? 'color: var(--warning-color)' : '';
                html += `<li style="${severityColor}">${issue.description}</li>`;
            });
            
            if (security.issues_found.length > 3) {
                html += `<li><em>...and ${security.issues_found.length - 3} more issues</em></li>`;
            }
            html += '</ul></div>';
        }
        
        securityContent.innerHTML = html;
    }
    
    // Display dependency information
    function displayDependencies(dependencies) {
        const depsContent = document.getElementById('dependencies-content');
        const outdated = dependencies.outdated_count || 0;
        const vulnerable = dependencies.vulnerable_count || 0;
        const vulnerableList = dependencies.vulnerable_dependencies || [];
        
        let html = `
            <div class="issue-stat">
                <span class="issue-stat-label">Outdated Packages:</span>
                <span class="issue-stat-value ${outdated > 10 ? 'critical' : outdated > 5 ? 'warning' : ''}">${outdated}</span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Vulnerable Packages:</span>
                <span class="issue-stat-value ${vulnerable > 0 ? 'critical' : 'success'}">${vulnerable}</span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Last Updated:</span>
                <span class="issue-stat-value">${dependencies.last_update || 'Unknown'}</span>
            </div>
        `;
        
        // Add vulnerable package details if available
        if (vulnerableList.length > 0) {
            html += '<div style="margin-top: 10px; font-size: 0.85em;">';
            html += '<strong>Vulnerable packages:</strong><ul style="margin: 5px 0; padding-left: 20px;">';
            vulnerableList.slice(0, 3).forEach(pkg => {
                html += `<li style="color: var(--danger-color)">${pkg.name} - ${pkg.vulnerability}</li>`;
            });
            if (vulnerableList.length > 3) {
                html += `<li><em>...and ${vulnerableList.length - 3} more</em></li>`;
            }
            html += '</ul></div>';
        }
        
        depsContent.innerHTML = html;
    }
    
    // Display CI/CD information
    function displayCICD(cicd) {
        const cicdContent = document.getElementById('cicd-content');
        const hasCICD = cicd.has_ci_cd || false;
        const status = cicd.last_run_status || 'Unknown';
        
        let statusClass = '';
        if (status === 'success') statusClass = 'success';
        else if (status === 'failure') statusClass = 'critical';
        else if (status === 'unstable') statusClass = 'warning';
        else if (status === 'In Progress') statusClass = 'warning';
        
        cicdContent.innerHTML = `
            <div class="issue-stat">
                <span class="issue-stat-label">CI/CD Pipeline:</span>
                <span class="issue-stat-value ${hasCICD ? 'success' : 'warning'}">
                    ${hasCICD ? 'Configured' : 'Not Found'}
                </span>
            </div>
            ${hasCICD ? `
                <div class="issue-stat">
                    <span class="issue-stat-label">Pipeline Type:</span>
                    <span class="issue-stat-value">${cicd.pipeline_type || 'GitHub Actions'}</span>
                </div>
                <div class="issue-stat">
                    <span class="issue-stat-label">Last Run:</span>
                    <span class="issue-stat-value ${statusClass}">${status}</span>
                </div>
            ` : ''}
        `;
    }
    
    // Display documentation information
    function displayDocumentation(docs) {
        const docsContent = document.getElementById('docs-content');
        const hasReadme = docs.has_readme || false;
        const hasLicense = docs.has_license || false;
        const hasContributing = docs.has_contributing || false;
        const hasSecurityPolicy = docs.has_security_policy || false;
        
        docsContent.innerHTML = `
            <div class="issue-stat">
                <span class="issue-stat-label">README:</span>
                <span class="issue-stat-value ${hasReadme ? 'success' : 'warning'}">
                    ${hasReadme ? `Present (${docs.readme_size} bytes)` : 'Missing'}
                </span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">LICENSE:</span>
                <span class="issue-stat-value ${hasLicense ? 'success' : 'warning'}">
                    ${hasLicense ? docs.license_type || 'Present' : 'Missing'}
                </span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Contributing Guide:</span>
                <span class="issue-stat-value ${hasContributing ? 'success' : ''}>
                    ${hasContributing ? 'Present' : 'Missing'}
                </span>
            </div>
            <div class="issue-stat">
                <span class="issue-stat-label">Security Policy:</span>
                <span class="issue-stat-value ${hasSecurityPolicy ? 'success' : ''}>
                    ${hasSecurityPolicy ? 'Present' : 'Missing'}
                </span>
            </div>
        `;
    }
    
    // Display AI insights
    function displayAIInsights(insights) {
        const aiSection = document.getElementById('ai-insights');
        const aiContent = document.getElementById('ai-content');
        
        if (insights && insights.length > 0) {
            aiSection.style.display = 'block';
            
            let insightsHTML = '';
            insights.forEach(insight => {
                insightsHTML += `<div class="ai-insight">${insight}</div>`;
            });
            
            aiContent.innerHTML = insightsHTML;
        }
    }
    
    // Display recommendations
    function displayRecommendations(recommendations) {
        const recSection = document.getElementById('recommendations');
        const recList = document.getElementById('recommendations-list');
        
        if (recommendations && recommendations.length > 0) {
            recSection.style.display = 'block';
            
            let recHTML = '';
            recommendations.forEach(rec => {
                const priorityClass = rec.priority.toLowerCase();
                recHTML += `
                    <div class="recommendation-item ${priorityClass}">
                        <span class="recommendation-priority ${priorityClass}">${rec.priority}</span>
                        <div class="recommendation-message">${rec.message}</div>
                        <div class="recommendation-action">${rec.action}</div>
                    </div>
                `;
            });
            
            recList.innerHTML = recHTML;
        }
    }
    
    // Show error message
    function showError(message) {
        errorSection.style.display = 'block';
        document.getElementById('error-message').textContent = message;
        errorSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    
    // Reset the analysis
    function resetAnalysis() {
        repoInput.value = '';
        clearPreviousResults();
        progressSection.style.display = 'none';
        resultsSection.style.display = 'none';
        errorSection.style.display = 'none';
        currentAnalysis = null;
        
        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    
    // Download report as JSON
    function downloadReport() {
        if (!currentAnalysis) return;
        
        // Add timestamp to the report
        const report = {
            ...currentAnalysis,
            generated_at: new Date().toISOString(),
            report_version: '2.0'
        };
        
        const dataStr = JSON.stringify(report, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
        const exportName = `health-report-${currentAnalysis.repository.name}-${Date.now()}.json`;
        
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportName);
        linkElement.click();
    }
});