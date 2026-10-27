# Attack‑Path Analysis Report

## Risk Summary

- prob:
  - 0.6120000000000001
- criticality:
  - 10
- score:
  - 6.120000000000001
- band:
  - 'High'

## Hardening Plan

- kept:
- - - 'internet'
- - 'web-prod'
- - - 'app-srv'
- - 'db-main'
- - - 'web-prod'
- - 'app-srv'
- - - 'hr-pc'
- - 'file-share'
- - - 'mail-gw'
- - 'hr-pc'
- - - 'vpn-gw'
- - 'dev-pc'
- - - 'internet'
- - 'mail-gw'
- - - 'dev-pc'
- - 'app-srv'
- - - 'file-share'
- - 'domain-ctrl'
- removed:
- - - 'internet'
- - 'vpn-gw'
- - - 'dev-pc'
- - 'domain-ctrl'
- - - 'web-prod'
- - 'db-main'

## Segments

- 0:
  - {'domain-ctrl', 'internet', 'file-share', 'web-prod', 'hr-pc', 'dev-pc', 'db-main', 'app-srv', 'vpn-gw', 'mail-gw'}
