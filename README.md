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
