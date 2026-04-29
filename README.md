# YAML-Based Detection Engine

The analyzer supports external YAML-based detection rules.

Rules are loaded dynamically from the `rules/` directory, allowing detections to be added or modified without changing Python source code.

Example rule:

```yaml
title: Suspicious DNS TLD Detected
type: dns
severity: MEDIUM

conditions:
  contains:
    - ".ru"
    - ".xyz"
```

This architecture is inspired by modern detection engineering workflows such as Sigma and SIEM rule pipelines.
