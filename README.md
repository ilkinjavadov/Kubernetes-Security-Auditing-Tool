# Kube-Sec-Audit

A comprehensive Kubernetes security auditing tool integrating multiple modules to detect misconfigurations, vulnerabilities, and risks across your cluster.

## Features

- RBAC Analyzer: Detects overprivileged roles and bindings  
- Pod Security Analyzer: Checks pod security contexts for risky settings  
- NetworkPolicy Analyzer: Identifies missing or overly permissive network policies  
- Image & Tag Scanner: Detects use of `latest` tags and outdated images  
- Privileged Pod Detector: Finds pods with privileged access, host network, or hostPath mounts  
- Secret Detector: Finds exposed secrets in cluster resources  
- Modular design with unified JSON reporting

## Installation

1. Clone the repository:  
   ```bash
   git clone https://github.com/yourusername/kube-sec-audit.git
   cd kube-sec-audit
   ```

Build the binary:

bash
Copy
Edit
go build -o kube-sec-audit cmd/main.go
Usage
Run all modules:

bash
Copy
Edit
./kube-sec-audit -k ~/.kube/config -m all -o report.json
Run specific modules:

bash
Copy
Edit
./kube-sec-audit -k ~/.kube/config -m rbac,podsec,imagecheck -o partial-report.json
Flags
-k : Path to kubeconfig file (required)

-m : Comma-separated list of modules to run (default: all)

-o : Output report file path (default: report.json)

Modules
rbac: Analyze RBAC roles and bindings

podsec: Analyze Pod security contexts

netpol: Analyze NetworkPolicies

imagecheck: Scan container images and tags

privilege: Detect privileged pods and risky host access

secrets: Detect exposed secrets

kubeaudit: Additional Kubernetes audit checks

imagescanner: Scan images for vulnerabilities (future)

Contributing
Contributions are welcome! Please open issues or pull requests.
