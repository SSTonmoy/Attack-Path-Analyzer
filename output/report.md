# Attack‑Path Analysis Report

## Risk Summary

- prob:
  - 0.504
- criticality:
  - 10
- score:
  - 5.04
- band:
  - 'High'

## Hardening Plan

- kept:
- - - 'internet'
- - 'web01'
- - - 'web01'
- - 'app01'
- - - 'mail01'
- - 'admin-pc'
- - - 'app01'
- - 'db01'
- - - 'app01'
- - 'file01'
- - - 'admin-pc'
- - 'db01'
- removed:
- - - 'internet'
- - 'mail01'
- - - 'file01'
- - 'db01'
- - - 'web01'
- - 'db01'

## Segments

- 0:
  - {'web01', 'admin-pc', 'internet', 'app01', 'mail01', 'db01', 'file01'}
