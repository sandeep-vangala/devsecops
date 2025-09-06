# Application Security Testing Notes

## Static Application Security Testing (SAST)

- **Definition**: Analyzes source code or binaries for vulnerabilities without executing the program.
- **Tool**: Horusec
  - Open-source SAST tool for identifying vulnerabilities in code.
  - GitHub: [https://github.com/ZupIT/horusec](https://github.com/ZupIT/horusec)
  - **Docker Command**:
    ```bash
    docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src horuszup/horusec-cli:v2.9.0-beta.3 horusec start -p /src -P $(pwd)
    ```
  - Maps current directory to `/src` in the container for analysis.
  - Suitable for integration into CI/CD pipelines for automated code scanning.

## Dynamic Application Security Testing (DAST)

- **Definition**: Tests a running application through its UI or API for vulnerabilities like SQL injection and buffer overflows.
- **Characteristics**:
  - Black-box testing: Limited visibility into internal code structure.
  - Primarily used for manual testing (e.g., penetration testing).
  - Can be embedded in CI/CD pipelines but less suited for automation compared to SAST.
- **Tools**:
  - **OWASP ZAP**: Open-source DAST tool, suitable for manual and some automated testing.
  - **Burp Suite**: Popular commercial tool for manual penetration testing.
- **Use Case**: Best for testing live applications, identifying runtime vulnerabilities.

## Software Composition Analysis (SCA)

- **Definition**: Analyzes software dependencies for known vulnerabilities and outdated versions.
- **Purpose**:
  - Identifies vulnerabilities in third-party dependencies (e.g., libraries, frameworks).
  - Checks for CVEs (Common Vulnerabilities and Exposures) in dependencies.
  - Ensures dependencies are up-to-date to mitigate risks.
- **Example**:
  - `package.json` might include:
    ```json
    "dependencies": {
      "array-flatten": "1.1.1",
      "node-emoji": "1.0.0"
    }
    ```
  - `node-emoji:1.0.0` may depend on `lodash:1.0.0` and `methods:1.0.0`, forming a dependency tree.
  - SCA tools flag outdated or vulnerable dependencies (e.g., `lodash:1.0.0` vulnerable to CVEs).
- **Characteristics**:
  - A subset of SAST, as it analyzes source code for dependency management.
  - Well-suited for CI/CD pipelines.
  - Works best with open-source components.
- **Tool**: **Snyk**
  - Checks application dependencies for vulnerabilities and suggests upgrades.
  - Example: Flags `lodash:1.0.0` as vulnerable and recommends upgrading to a safer version.

## Cloud-Native Application Protection Platform (CNAPP)

- **Definition**: A comprehensive security platform combining multiple security tools to protect cloud-native applications.
- **Components**:
  - **Cloud Security Posture Management (CSPM)**: Monitors and manages cloud configuration risks.
  - **Cloud Workload Protection Platform (CWPP)**: Secures workloads (e.g., VMs, containers, serverless).
  - **SAST/SCA/DAST Integration**: Incorporates static, dynamic, and dependency analysis for holistic application security.
  - **Container and Kubernetes Security**: Scans container images and orchestrators for vulnerabilities.
  - **Infrastructure as Code (IaC) Scanning**: Analyzes IaC templates (e.g., Terraform, CloudFormation) for misconfigurations.
- **Benefits**:
  - Unified security for cloud-native environments (e.g., AWS, Azure, GCP).
  - Continuous monitoring and protection across development, deployment, and runtime.
  - Integrates with CI/CD pipelines for DevSecOps workflows.
- **Use Case**: Provides end-to-end security for modern applications, covering code, dependencies, infrastructure, and runtime environments.
- **Tools**: Examples include Snyk, Aqua Security, Sysdig, and Prisma Cloud (commercial).

# Key Security Principles for DevSecOps

The following notes cover essential security principles and frameworks relevant to a DevSecOps interview, focusing on integrating security into development and operations workflows.

## Defense in Depth

- **Definition**: A security strategy that employs multiple layers of controls to protect systems, applications, or data, ensuring no single point of failure compromises security.
- **Concept**: Instead of relying on one security measure, multiple overlapping defenses are implemented to mitigate risks. If one layer is breached, others remain to protect the system.
- **Example** (Login Page Security):
  - **Strong Password Requirements**: Enforce complex passwords (e.g., minimum length, mix of characters).
  - **CAPTCHA**: Display after multiple failed login attempts to prevent automated brute-force attacks.
  - **Two-Factor Authentication (2FA)**: Require a secondary verification method (e.g., SMS code, authenticator app).
  - **Email Confirmation**: Trigger for logins from unrecognized IP addresses or locations.
- **DevSecOps Relevance**:
  - Integrate automated security checks (e.g., SAST, DAST) at multiple pipeline stages (code, build, deploy).
  - Use infrastructure as code (IaC) scanning to secure cloud configurations.
  - Implement runtime protection (e.g., Web Application Firewall) to complement code-level security.
- **Benefits**:
  - Reduces the likelihood of a single vulnerability leading to a breach.
  - Enhances resilience through layered protections across the software development lifecycle (SDLC).
- **Interview Tip**: Highlight how defense in depth aligns with DevSecOps by embedding security at every stage (code, build, test, deploy, monitor).

## Least Privilege

- **Definition**: Grant users, processes, or systems only the minimum permissions necessary to perform their tasks, reducing the attack surface.
- **Concept**: Limiting access ensures that even if a component is compromised, the damage is contained.
- **Examples**:
  - **Developer Access**: Developers have read-only access to production environments, not full admin rights.
  - **Service Accounts**: CI/CD pipeline service accounts have specific permissions (e.g., deploy to a single environment) rather than broad access.
  - **Container Security**: Containers run with minimal privileges (e.g., non-root users) to limit exploitation.
- **DevSecOps Relevance**:
  - Use role-based access control (RBAC) in CI/CD tools (e.g., Jenkins, GitLab) to restrict pipeline actions.
  - Apply least privilege to cloud resources via IAM policies (e.g., AWS IAM roles with specific permissions).
  - Automate privilege audits using tools like HashiCorp Vault or cloud-native IAM solutions.
- **Benefits**:
  - Minimizes the impact of compromised credentials or components.
  - Aligns with zero-trust architecture, a key DevSecOps principle.
- **Interview Tip**: Discuss implementing least privilege in CI/CD pipelines, such as restricting container privileges or using temporary credentials for deployments.

## Authorization and Authentication

- **Authentication (AuthN)**:
  - **Definition**: Verifying the identity of a user, system, or process (e.g., "Who are you?").
  - **Examples**:
    - Username/password login.
    - OAuth tokens for API authentication.
    - Certificate-based authentication for services.
  - **DevSecOps Practices**:
    - Integrate secure authentication in applications (e.g., OAuth 2.0, OpenID Connect).
    - Use secrets management tools (e.g., AWS Secrets Manager, HashiCorp Vault) to securely store credentials.
    - Implement single sign-on (SSO) for streamlined and secure access across tools.
- **Authorization (AuthZ)**:
  - **Definition**: Determining what an authenticated entity is allowed to do (e.g., "What can you access?").
  - **Examples**:
    - RBAC: Assign roles with specific permissions (e.g., developer vs. admin).
    - Attribute-based access control (ABAC): Permissions based on attributes (e.g., location, time).
  - **DevSecOps Practices**:
    - Enforce fine-grained access controls in CI/CD pipelines and cloud environments.
    - Use policy-as-code tools (e.g., Open Policy Agent) to define and enforce authorization rules.
    - Regularly audit permissions to prevent privilege creep.
- **DevSecOps Relevance**:
  - Embed AuthN/AuthZ checks in application code and infrastructure configurations.
  - Automate security testing for authentication vulnerabilities (e.g., weak passwords, session management flaws).
  - Monitor and log authentication/authorization events for anomaly detection.
- **Interview Tip**: Explain how AuthN/AuthZ are implemented in a DevSecOps pipeline, such as securing API endpoints or using IAM roles for deployments.

## CIS Benchmarks

- **Definition**: A set of best-practice configuration guidelines developed by the Center for Internet Security (CIS) to secure systems, applications, and cloud environments.
- **Purpose**: Provide standardized, vendor-neutral recommendations to harden systems against common threats.
- **Examples**:
  - **CIS Docker Benchmark**: Guidelines for securing Docker containers (e.g., run containers as non-root, limit host filesystem access).
  - **CIS AWS Foundations Benchmark**: Recommendations for securing AWS services (e.g., enable MFA, encrypt S3 buckets).
  - **CIS Kubernetes Benchmark**: Best practices for securing Kubernetes clusters (e.g., enable RBAC, restrict anonymous access).
- **DevSecOps Relevance**:
  - Use CIS Benchmarks to validate IaC templates (e.g., Terraform, CloudFormation) in CI/CD pipelines.
  - Automate compliance checks using tools like AWS Config, Inspec, or OpenSCAP.
  - Integrate benchmark scans into pre-deployment stages to ensure secure configurations.
- **Benefits**:
  - Provides a measurable standard for security compliance.
  - Reduces misconfiguration risks in cloud and containerized environments.
- **Interview Tip**: Mention using CIS Benchmarks to harden cloud infrastructure or Kubernetes clusters in a DevSecOps workflow, emphasizing automation.

## CIS Controls

Below is a detailed set of notes on the **CIS Critical Security Controls (Version 8.1)** based on the provided document from the Center for Internet Security (CIS) website. These notes are tailored for a **DevSecOps interview**, emphasizing how these controls integrate with DevSecOps practices to strengthen cybersecurity in development and operations workflows.

---

<xaiArtifact artifact_id="7c60d9ce-4b0f-4fe9-b0ec-d0ca3fde2ea4" artifact_version_id="05111843-8b48-4103-b36d-4c7be00d266b" title="CIS_Critical_Security_Controls_v8.1_Notes_for_DevSecOps.md" contentType="text/markdown">

# CIS Critical Security Controls v8.1 Notes for DevSecOps

The **CIS Critical Security Controls (CIS Controls)** are a prioritized, prescriptive, and simplified set of cybersecurity best practices designed to strengthen an organization's cybersecurity posture. Version 8.1, released in June 2024, includes updates for alignment with industry standards (e.g., NIST CSF 2.0), revised asset classes, updated safeguard descriptions, and the addition of a **Governance** security function. These controls are particularly relevant for **DevSecOps**, as they provide actionable guidance for embedding security into the software development lifecycle (SDLC) and CI/CD pipelines.

Below is a detailed overview of the **18 CIS Controls** with their relevance to DevSecOps practices, focusing on automation, integration, and real-world application.

---

## CIS Control 1: Inventory and Control of Enterprise Assets

- **Description**: Actively manage (inventory, track, and correct) all enterprise assets, including end-user devices, network devices, IoT devices, and servers, whether on-premises, virtual, remote, or in cloud environments. This ensures visibility into assets that need monitoring and protection, identifying unauthorized or unmanaged assets for removal or remediation.
- **DevSecOps Relevance**:
  - Use automated asset discovery tools (e.g., AWS Config, ServiceNow) in CI/CD pipelines to maintain an up-to-date inventory.
  - Integrate with Infrastructure as Code (IaC) to track cloud resources (e.g., EC2 instances, Lambda functions).
  - Implement monitoring to detect shadow IT or unauthorized assets in development and production environments.
- **Example**: Scan for unmanaged containers in a Kubernetes cluster using tools like Sysdig or Prisma Cloud.
- **Interview Tip**: Highlight automating asset inventory with tools like HashiCorp Vault or cloud-native discovery services to ensure compliance and reduce risks in dynamic cloud environments.

---

## CIS Control 2: Inventory and Control of Software Assets

- **Description**: Actively manage all software (operating systems, applications) on the network to ensure only authorized software is installed and executed, preventing unauthorized or unmanaged software.
- **DevSecOps Relevance**:
  - Use **Software Composition Analysis (SCA)** tools (e.g., Snyk, Dependabot) to track and secure software dependencies in CI/CD pipelines.
  - Automate software inventory with tools like JFrog Artifactory or Nexus Repository to enforce approved software lists.
  - Block unauthorized software execution using allowlisting (e.g., AppLocker, Kubernetes Pod Security Policies).
- **Example**: Integrate Snyk into a GitHub Actions pipeline to scan `package.json` for outdated or vulnerable dependencies.
- **Interview Tip**: Discuss how SCA tools in DevSecOps pipelines ensure only secure, approved software is deployed, aligning with least privilege principles.

---

## CIS Control 3: Data Protection

- **Description**: Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.
- **DevSecOps Relevance**:
  - Implement data classification in CI/CD pipelines to tag sensitive data (e.g., PII, PHI) using tools like AWS Macie.
  - Use encryption (e.g., AWS KMS, HashiCorp Vault) for data at rest and in transit in development and production.
  - Automate data retention and disposal policies using IaC (e.g., Terraform scripts for S3 lifecycle rules).
- **Example**: Encrypt sensitive data in a PostgreSQL database managed by a Helm chart in a Kubernetes deployment.
- **Interview Tip**: Emphasize automating data protection in pipelines, such as scanning for sensitive data leaks in code repositories with tools like TruffleHog.

---

## CIS Control 4: Secure Configuration of Enterprise Assets and Software

- **Description**: Establish and maintain secure configurations for enterprise assets (devices, servers, IoT) and software (OS, applications).
- **DevSecOps Relevance**:
  - Use **CIS Benchmarks** to validate secure configurations in CI/CD pipelines (e.g., InSpec, OpenSCAP).
  - Automate configuration checks for cloud resources (e.g., AWS Config Rules) and containers (e.g., Docker CIS Benchmark).
  - Enforce secure IaC templates (e.g., Terraform, CloudFormation) using tools like Checkov.
- **Example**: Scan Kubernetes cluster configurations for compliance with CIS Kubernetes Benchmark using kube-bench.
- **Interview Tip**: Discuss integrating CIS Benchmarks into DevSecOps workflows to ensure secure infrastructure deployments, emphasizing automation.

---

## CIS Control 5: Account Management

- **Description**: Use processes and tools to assign and manage authorization for user, administrator, and service account credentials.
- **DevSecOps Relevance**:
  - Implement role-based access control (RBAC) in CI/CD tools (e.g., GitLab, Jenkins) to manage pipeline permissions.
  - Use secrets management tools (e.g., AWS Secrets Manager, HashiCorp Vault) to securely handle credentials in pipelines.
  - Automate account provisioning/deprovisioning with tools like Okta or AWS IAM.
- **Example**: Use temporary credentials for CI/CD pipelines via AWS IAM roles to limit exposure.
- **Interview Tip**: Highlight least privilege and automation of account management in DevSecOps, such as using Vault for dynamic secrets.

---

## CIS Control 6: Access Control Management

- **Description**: Create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts.
- **DevSecOps Relevance**:
  - Enforce fine-grained access controls in cloud environments using IAM policies (e.g., AWS, Azure AD).
  - Use policy-as-code tools (e.g., Open Policy Agent) to define and enforce access rules in CI/CD pipelines.
  - Monitor access patterns for anomalies using tools like Splunk or AWS CloudTrail.
- **Example**: Restrict developer access to production Kubernetes namespaces using RBAC and network policies.
- **Interview Tip**: Discuss implementing zero-trust principles in DevSecOps by automating access control checks and monitoring.

---

## CIS Control 7: Continuous Vulnerability Management

- **Description**: Continuously assess and track vulnerabilities across enterprise assets, remediating them to minimize attack windows. Monitor public/private threat and vulnerability sources.
- **DevSecOps Relevance**:
  - Integrate **SAST** (e.g., Horusec), **DAST** (e.g., OWASP ZAP), and **SCA** (e.g., Snyk) into CI/CD pipelines for vulnerability scanning.
  - Automate patch management using tools like Ansible or AWS Systems Manager.
  - Use threat intelligence feeds (e.g., MITRE ATT&CK) to prioritize remediation in DevSecOps workflows.
- **Example**: Run Snyk in a GitHub Actions pipeline to scan for vulnerabilities in code and dependencies before deployment.
- **Interview Tip**: Emphasize shift-left security by integrating vulnerability scanning early in the SDLC, with automated remediation.

---

## CIS Control 8: Audit Log Management

- **Description**: Collect, alert, review, and retain audit logs to detect, understand, or recover from attacks.
- **DevSecOps Relevance**:
  - Centralize logs using tools like ELK Stack, Splunk, or AWS CloudWatch in CI/CD pipelines.
  - Automate log analysis for security events using SIEM solutions (e.g., Datadog, Splunk).
  - Ensure logs are tamper-proof and retained per compliance requirements (e.g., GDPR, HIPAA).
- **Example**: Configure AWS CloudTrail to log API calls and analyze them for unauthorized access in a pipeline.
- **Interview Tip**: Discuss logging as a critical DevSecOps practice for incident detection and compliance, emphasizing automation.

---

## CIS Control 9: Email and Web Browser Protections

- **Description**: Improve protections and detections for email and web-based threats, which exploit human behavior.
- **DevSecOps Relevance**:
  - Integrate email security scanning (e.g., DMARC, SPF) into CI/CD for applications with email functionality.
  - Use web application firewalls (WAFs) like AWS WAF or Cloudflare to protect web apps in production.
  - Automate phishing simulation tests in CI/CD to train developers on secure coding practices.
- **Example**: Scan for phishing vulnerabilities in a web app using OWASP ZAP in a CI/CD pipeline.
- **Interview Tip**: Highlight protecting web and email vectors in DevSecOps by automating security tests and deploying WAFs.

---

## CIS Control 10: Malware Defenses

- **Description**: Prevent or control the installation, spread, and execution of malicious applications, code, or scripts.
- **DevSecOps Relevance**:
  - Integrate antivirus/malware scanning into CI/CD pipelines (e.g., ClamAV for container images).
  - Use runtime protection tools (e.g., Falco, CrowdStrike) to detect malicious behavior in production.
  - Enforce code signing to ensure only trusted code is deployed.
- **Example**: Scan Docker images for malware using Trivy in a Jenkins pipeline.
- **Interview Tip**: Discuss automating malware defenses in DevSecOps, such as scanning container images and monitoring runtime behavior.

---

## CIS Control 11: Data Recovery

- **Description**: Establish and maintain data recovery practices to restore assets to a pre-incident state.
- **DevSecOps Relevance**:
  - Automate backups using IaC (e.g., Terraform for S3 bucket backups).
  - Test recovery processes in CI/CD pipelines using chaos engineering tools (e.g., Chaos Monkey).
  - Ensure backups are encrypted and isolated (e.g., AWS Backup with KMS encryption).
- **Example**: Automate nightly backups of an RDS database and test restores in a staging environment.
- **Interview Tip**: Highlight automating and testing data recovery in DevSecOps to ensure business continuity.

---

## CIS Control 12: Network Infrastructure Management

- **Description**: Manage network devices to prevent attackers from exploiting vulnerable services and access points.
- **DevSecOps Relevance**:
  - Use IaC to enforce secure network configurations (e.g., VPC settings in AWS).
  - Automate network device compliance checks using tools like Nmap or Nessus.
  - Implement network segmentation in CI/CD pipelines for microservices architectures.
- **Example**: Use Terraform to configure secure VPCs with private subnets in a CI/CD pipeline.
- **Interview Tip**: Discuss securing network infrastructure in DevSecOps by automating configurations and monitoring.

---

## CIS Control 13: Network Monitoring and Defense

- **Description**: Operate processes and tools for comprehensive network monitoring and defense against security threats.
- **DevSecOps Relevance**:
  - Deploy network monitoring tools (e.g., Zeek, Suricata) in CI/CD pipelines to detect anomalies.
  - Use cloud-native monitoring (e.g., AWS GuardDuty) for real-time threat detection.
  - Integrate network security tests into pre-deployment stages.
- **Example**: Monitor Kubernetes pod traffic for anomalies using Calico in a CI/CD pipeline.
- **Interview Tip**: Emphasize real-time monitoring in DevSecOps for proactive threat detection and response.

---

## CIS Control 14: Security Awareness and Skills Training

- **Description**: Establish a security awareness program to train the workforce to reduce cybersecurity risks.
- **DevSecOps Relevance**:
  - Integrate security training into CI/CD workflows (e.g., OWASP Top 10 training for developers).
  - Automate security awareness tests (e.g., phishing simulations) in pipelines.
  - Use tools like Secure Code Warrior to train developers on secure coding practices.
- **Example**: Require developers to complete secure coding training before merging code in GitHub.
- **Interview Tip**: Highlight embedding security training in DevSecOps to foster a security-first culture.

---

## CIS Control 15: Service Provider Management

- **Description**: Evaluate service providers handling sensitive data or critical IT platforms to ensure they protect data appropriately.
- **DevSecOps Relevance**:
  - Automate third-party risk assessments in CI/CD pipelines (e.g., using Black Kite or SecurityScorecard).
  - Enforce secure API integrations with third-party services (e.g., OAuth, JWT validation).
  - Monitor vendor compliance using cloud-native tools (e.g., AWS Trusted Advisor).
- **Example**: Validate a third-party API’s security posture using OWASP ZAP in a pipeline.
- **Interview Tip**: Discuss vetting third-party services in DevSecOps to ensure supply chain security.

---

## CIS Control 16: Application Software Security

- **Description**: Manage the security lifecycle of in-house, hosted, or acquired software to prevent, detect, and remediate weaknesses.
- **DevSecOps Relevance**:
  - Integrate **SAST** (e.g., Horusec), **DAST** (e.g., OWASP ZAP), and **SCA** (e.g., Snyk) into CI/CD pipelines.
  - Use secure coding frameworks (e.g., OWASP Secure Coding Practices) in development.
  - Automate application penetration testing in pre-deployment stages.
- **Example**: Run Horusec SAST scans in a GitLab pipeline to detect code vulnerabilities.
- **Interview Tip**: Emphasize shift-left security in DevSecOps by integrating application security testing early in the SDLC.

---

## CIS Control 17: Incident Response Management

- **Description**: Establish an incident response capability with policies, plans, procedures, roles, training, and communications.
- **DevSecOps Relevance**:
  - Automate incident detection and response using SOAR tools (e.g., Demisto, Splunk SOAR).
  - Integrate incident response playbooks into CI/CD pipelines for rapid recovery.
  - Simulate incidents in staging environments using chaos engineering tools.
- **Example**: Automate incident alerts for failed pipeline security checks using PagerDuty.
- **Interview Tip**: Discuss automating incident response in DevSecOps to minimize downtime and ensure compliance.

---

## CIS Control 18: Penetration Testing

- **Description**: Test the effectiveness of controls by simulating attacker actions to identify and exploit weaknesses.
- **DevSecOps Relevance**:
  - Integrate automated penetration testing tools (e.g., Metasploit, Burp Suite) into CI/CD pipelines.
  - Conduct regular manual penetration tests to complement automated scans.
  - Use findings to improve pipeline security configurations and code quality.
- **Example**: Run OWASP ZAP in a CI/CD pipeline to simulate attacks on a web application.
- **Interview Tip**: Highlight balancing automated and manual penetration testing in DevSecOps to ensure robust security.

---

## Key DevSecOps Integration Points

- **Automation**: Automate CIS Controls using CI/CD tools (e.g., Jenkins, GitHub Actions) for vulnerability scanning, configuration checks, and logging.
- **Shift-Left Security**: Embed controls like SAST, DAST, and SCA early in the SDLC to catch vulnerabilities before deployment.
- **Zero Trust**: Apply least privilege, access control, and continuous monitoring to align with zero-trust principles.
- **Compliance**: Use CIS Controls to meet regulatory requirements (e.g., GDPR, HIPAA, PCI DSS) by automating evidence collection.
- **Tooling**: Leverage tools like Snyk, OWASP ZAP, Horusec, and cloud-native solutions (e.g., AWS Security Hub) to implement controls.

---

## Interview Preparation Tips

- **Demonstrate Practical Knowledge**: Provide examples of implementing CIS Controls in CI/CD pipelines (e.g., scanning dependencies with Snyk or securing Kubernetes with CIS Benchmarks).
- **Highlight Automation**: Emphasize automating controls (e.g., vulnerability scanning, logging, configuration checks) to reduce manual effort and improve efficiency.
- **Connect to DevSecOps Principles**: Link CIS Controls to defense in depth, least privilege, and AuthN/AuthZ for a holistic security approach.
- **Discuss Challenges**: Address challenges like managing false positives in scans or ensuring developer buy-in for security practices.
- **Real-World Scenarios**: Be ready to explain how you’d apply CIS Controls in a DevSecOps pipeline, such as securing a microservices architecture or cloud deployment.

---

**Source**: [CIS Critical Security Controls List](https://www.cisecurity.org/controls/cis-controls-list)[](https://www.cisecurity.org/controls/cis-controls-list)

</xaiArtifact>
