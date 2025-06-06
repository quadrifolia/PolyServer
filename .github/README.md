# PolyServer GitHub Workflows

This directory contains automated CI/CD workflows for testing and validating the PolyServer foundation.

## Workflows Overview

### 🔧 `test-server-hardening.yml`
**Primary CI workflow for testing server hardening and configuration**

**Triggers:**
- Pull requests to `main` branch
- Pushes to `main` branch  
- Changes to `templates/` or `scripts/` directories
- Manual dispatch

**Jobs:**
1. **validate-templates** - Validates shell script and YAML syntax, tests configuration generation
2. **test-server-hardening** - Matrix test (Docker/Bare Metal modes) of actual server hardening in containers
3. **test-local-docker-scripts** - Tests the local Docker testing workflow
4. **security-validation** - Validates DSGVO compliance and checks for security issues
5. **test-summary** - Reports overall test results

**Key Features:**
- Tests both Docker and Bare Metal deployment modes
- Validates template syntax and configuration generation
- Runs actual server hardening script in containerized environment
- Verifies security configurations and log rotation setup
- Tests DSGVO compliance functionality

### 🛡️ `security-scan.yml`
**Comprehensive security and vulnerability scanning**

**Triggers:**
- Pull requests to `main` branch
- Pushes to `main` branch
- Weekly schedule (Sundays at 2 AM UTC)
- Manual dispatch

**Jobs:**
1. **secret-scanning** - Scans for exposed credentials using TruffleHog
2. **container-vulnerability-scan** - Scans built containers for vulnerabilities using Trivy
3. **dependency-scan** - Audits external dependencies and downloads
4. **code-quality-scan** - Runs ShellCheck and validates configuration files
5. **security-report** - Generates comprehensive security summary report

**Key Features:**
- Automated secret detection
- Container vulnerability scanning
- Supply chain security analysis
- Code quality and security analysis
- Automated security reporting with PR comments

### 📚 `docs-validation.yml`
**Documentation validation and consistency checking**

**Triggers:**
- Pull requests to `main` branch
- Pushes to `main` branch
- Changes to `*.md` files
- Manual dispatch

**Jobs:**
1. **validate-documentation** - Validates markdown syntax, links, and content structure
2. **create-link-check-config** - Creates configuration for link checking

**Key Features:**
- Markdown syntax validation
- Internal link checking
- Table of Contents consistency validation
- Required documentation section verification
- DSGVO documentation completeness check
- Documentation consistency validation

## Workflow Configuration

### Environment Variables
- `DOCKER_BUILDKIT: 1` - Enables Docker BuildKit for improved build performance
- `COMPOSE_DOCKER_CLI_BUILD: 1` - Uses Docker CLI for Docker Compose builds

### Artifacts Generated
- **secret-scan-results** - TruffleHog secret scanning results
- **container-vulnerability-scan** - Trivy vulnerability scan results  
- **security-summary-report** - Comprehensive security report
- **link-check-config** - Configuration for markdown link checking

### Matrix Testing
The server hardening workflow uses matrix strategy to test both deployment modes:
- `deployment_mode: [docker, baremetal]`

## Security Features

### Secret Scanning
- Uses TruffleHog to detect exposed credentials
- Scans full git history
- Generates alerts without failing builds (manual review required)

### Vulnerability Scanning  
- Scans container images with Trivy
- Checks for HIGH and CRITICAL severity vulnerabilities
- Provides detailed vulnerability reports

### Code Quality
- ShellCheck analysis for all shell scripts
- Hadolint analysis for Dockerfiles
- Configuration file format validation (YAML, JSON)

### Supply Chain Security
- Audits external downloads and dependencies
- Identifies potentially risky external sources
- Validates package installations

## Usage Guidelines

### For Contributors
1. All PRs to `main` automatically trigger the full test suite
2. Review any security scan warnings before merging
3. Ensure documentation is updated for significant changes
4. Address any failing tests before requesting review

### For Maintainers
1. Monitor weekly security scan reports
2. Review and address any critical vulnerabilities
3. Keep workflows updated with new security tools
4. Ensure proper secrets management in repository

### Manual Testing
All workflows can be triggered manually via GitHub Actions interface:
1. Go to Actions tab in GitHub repository
2. Select desired workflow
3. Click "Run workflow" button
4. Choose branch and any required parameters

## Monitoring and Alerts

### Workflow Status
- Check the Actions tab for workflow status
- Failed workflows prevent merging (required status checks)
- Security reports are posted as PR comments

### Security Alerts
- Critical security issues generate workflow failures
- Weekly security scans provide ongoing monitoring
- Secret detection alerts require manual review

### Performance Monitoring
- Workflow duration tracking
- Resource usage optimization
- Matrix job parallelization for faster feedback

## Troubleshooting

### Common Issues
1. **Template validation failures** - Check shell script syntax and YAML formatting
2. **Container build failures** - Verify Dockerfile syntax and base image availability
3. **Security scan false positives** - Review flagged items and update ignore patterns if needed
4. **Link check failures** - Update broken links or add to ignore patterns

### Debug Mode
Enable debug logging by setting `ACTIONS_STEP_DEBUG=true` in repository secrets.

### Workflow Maintenance
- Regularly update action versions (e.g., `actions/checkout@v4`)
- Keep security scanning tools updated
- Review and update ignore patterns as needed
- Monitor for deprecated GitHub Actions features

## Best Practices

### Security
- Never commit secrets or credentials
- Use repository secrets for sensitive configuration
- Regularly review security scan results
- Keep dependencies and tools updated

### Performance
- Use artifact caching where appropriate
- Parallelize independent jobs
- Optimize container builds with multi-stage builds
- Use matrix strategies for testing multiple configurations

### Maintenance
- Document any workflow modifications
- Test workflow changes on feature branches
- Monitor workflow performance and adjust as needed
- Keep this documentation updated with changes