# devsecops
horusec for SAST(static application security testing)  https://github.com/ZupIT/horusec
```
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src horuszup/horusec-cli:v2.9.0-beta.3 horusec start -p /src -P $(pwd)

```

DAST (Dynamic Application Security Testing). It can be used to test a  running application through its UI or API for common vulnerabilities such as SQL injection and buffer overflows
it can be embedded into CI/CD pipelines, but it would more be for completeness and are primarily aimed at manual testing as part of dedicated penetration test.
It is form of blackbox testing (it can't see everything behind the scenes).
Various options are available, but many DAST tools are more suitable for manual use rather than automation(commercial only).
An open-source choice might be OWASP ZAP, popular choice might be burp site.

SCA:

SCA == software composition analysis
software is rarely developed in isolation, or rather software is often developed with the help of third party dependencies. whether these eb frameworks or dependencies that have functionality you can  leverage instead of writing yourself (why reinvent the wheel)
example:
"dependencies": {
    "array-flatten": "1.1.1"
    "node-emoji": "1.0.0",
    > package.json contains "node-emoji":"1.0.0"
      1) depends upon "lodash":"1.0.0"
      2) depends upon "methods":"1.0.0"
    > can result in a dependency tree or dependency graph
    > we are trying to determine all of the use dependencies and whether or not they are on up to date versions or are vulnerable to any of CVEs
It is realistically a form of SAST, as it is testing the source code where the dependencies are managed.
similarly well suited for CI/CD pipelines(SAST)
It will test all of the "componenets" that make up the software for known vulnerabilities. These generally tend to work best with open source componenets.
It is these dependencies that can be flagged by SCA tools as being out of date and vulnerable. For example you might be using the version 1 of lodash ( A JavaScript library which provides common
functions) and an SCA tool might flag that this version is vulnerable to mutiple CVEs(Common Vulnerabilities and Exposures) and should be upgraded to the latest version.

we can use snyk tool for checking the dependencies for an application, if at all there is a need for upgradation of dependencies. 

CNAPP
