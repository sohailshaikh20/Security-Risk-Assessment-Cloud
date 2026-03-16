# DevSecOps Risk Assessment Report

**Generated:** 2026-03-16T22:46:06.161499+00:00

**Total findings:** 18

## Risk Summary

| Metric | Value |
|--------|-------|
| Average Risk | 0.5707 |
| Max Risk | 0.7545 |
| Critical | 1 |
| High | 12 |
| Medium | 0 |
| Low | 5 |

## Top 10 Highest Risk Findings

1. **[CRITICAL]** `trivy` | score=0.7545 | id=CVE-2023-37920 | asset=requirements.txt
   - type: CVE
   - stage: SCA
   - evidence: python-certifi: Removal of e-Tugra root certificate
   - contributions:
       severity: 0.392
       exposure: 0.06
       criticality: 0.075
       confidence: 0.1275
       freshness: 0.1

2. **[HIGH]** `checkov` | score=0.6985 | id=CKV_K8S_43 | asset=/main.tf
   - type: Image should use digest
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-39
   - contributions:
       severity: 0.28
       exposure: 0.06
       criticality: 0.075
       confidence: 0.12
       freshness: 0.1

3. **[HIGH]** `checkov` | score=0.6985 | id=CKV_K8S_22 | asset=/main.tf
   - type: Use read-only filesystem for containers where possible
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-21
   - contributions:
       severity: 0.28
       exposure: 0.06
       criticality: 0.075
       confidence: 0.12
       freshness: 0.1

4. **[HIGH]** `checkov` | score=0.6985 | id=CKV_K8S_28 | asset=/main.tf
   - type: Minimize the admission of containers with the NET_RAW capability
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-27
   - contributions:
       severity: 0.28
       exposure: 0.06
       criticality: 0.075
       confidence: 0.12
       freshness: 0.1

5. **[HIGH]** `trivy` | score=0.6865 | id=CVE-2023-50447 | asset=requirements.txt
   - type: CVE
   - stage: SCA
   - evidence: pillow: Arbitrary Code Execution via the environment parameter
   - contributions:
       severity: 0.324
       exposure: 0.06
       criticality: 0.075
       confidence: 0.1275
       freshness: 0.1

6. **[HIGH]** `trivy` | score=0.6625 | id=CVE-2023-30861 | asset=requirements.txt
   - type: CVE
   - stage: SCA
   - evidence: flask: Possible disclosure of permanent session cookie due to missing Vary: Cookie header
   - contributions:
       severity: 0.3
       exposure: 0.06
       criticality: 0.075
       confidence: 0.1275
       freshness: 0.1

7. **[HIGH]** `trivy` | score=0.6625 | id=CVE-2023-25577 | asset=requirements.txt
   - type: CVE
   - stage: SCA
   - evidence: python-werkzeug: high resource usage when parsing multipart form data with many fields
   - contributions:
       severity: 0.3
       exposure: 0.06
       criticality: 0.075
       confidence: 0.1275
       freshness: 0.1

8. **[HIGH]** `trivy` | score=0.6625 | id=CVE-2023-50782 | asset=requirements.txt
   - type: CVE
   - stage: SCA
   - evidence: python-cryptography: Bleichenbacher timing oracle attack against RSA decryption - incomplete fix for CVE-2020-25659
   - contributions:
       severity: 0.3
       exposure: 0.06
       criticality: 0.075
       confidence: 0.1275
       freshness: 0.1

9. **[HIGH]** `checkov` | score=0.6105 | id=CKV_DOCKER_2 | asset=/Dockerfile
   - type: Ensure that HEALTHCHECK instructions have been added to container images
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-healthcheck-instructions-have-been-added-to-container-images
   - contributions:
       severity: 0.2
       exposure: 0.06
       criticality: 0.075
       confidence: 0.12
       freshness: 0.1

10. **[HIGH]** `checkov` | score=0.6105 | id=CKV_DOCKER_3 | asset=/Dockerfile
   - type: Ensure that a user for the container has been created
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/docker-policies/docker-policy-index/ensure-that-a-user-for-the-container-has-been-created
   - contributions:
       severity: 0.2
       exposure: 0.06
       criticality: 0.075
       confidence: 0.12
       freshness: 0.1

## Asset Risk Summary

| Asset | Max Risk | Avg Risk | Count | Label |
|-------|----------|----------|-------|-------|
| requirements.txt | 0.7545 | 0.6652 | 6 | CRITICAL |
| /main.tf | 0.6985 | 0.6633 | 5 | HIGH |
| /Dockerfile | 0.6105 | 0.6105 | 2 | HIGH |
| app/starbucks/Dockerfile | 0.3487 | 0.3487 | 1 | LOW |
| app/starbucks/app.py | 0.3487 | 0.3487 | 4 | LOW |
