---
name: Bug report
about: Report a defect in toolwarden
title: ""
labels: bug
assignees: ""
---

## What happened

A short description of the defect.

## False allow check

Did the gate allow a call that policy should have denied? A bad input becoming
an allow is the invariant this library exists to hold, so confirmed cases are
treated as release blockers and become permanent corpus entries before the fix
ships. If yes, include the tool name, the argument shapes (redact the values,
keep the types), the principal, and the policies and normalizers registered on
the gate.

## Minimal reproduction

```python
# Smallest snippet that reproduces the problem: the policy and normalizer
# registrations, the Gate construction, and the decide() or wrapped call.
```

## The audit record

Paste the record line for the failing decision if you have it, from your
`on_decision` sink or `decision.record_line(ts=...)`. It is a single JSON
line, it contains no raw argument values, and it usually answers most
questions.

```
```

## Environment

- toolwarden version:
- Python version:
- Installed extras (none, openai-agents, anthropic, langchain):
- Attach point (wrap, openai_agents guardrail, anthropic_loop, langchain middleware, Claude Code hook):
- strict mode (True/False):

## Expected behaviour

What you expected instead, and why.
