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
- - - 'vpn-gw'
- - 'dev-pc'
- - - 'internet'
- - 'mail-gw'
- - - 'internet'
- - 'vpn-gw'
- - - 'mail-gw'
- - 'hr-pc'
- - - 'file-share'
- - 'domain-ctrl'
- removed:
- - - 'dev-pc'
- - 'app-srv'
- - - 'dev-pc'
- - 'domain-ctrl'
- - - 'web-prod'
- - 'db-main'

## Segments

- 0:
  - {'domain-ctrl', 'vpn-gw', 'mail-gw', 'web-prod', 'app-srv', 'db-main', 'internet', 'file-share', 'dev-pc', 'hr-pc'}
