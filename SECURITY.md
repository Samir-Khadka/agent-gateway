# Security Policy

## Reporting a vulnerability

If you find a security issue in Agent Gateway, please report it
privately — do not open a public issue. Email
**samirshirjan890@gmail.com** with a description of the issue, the
steps to reproduce it, and the version you tested against. You will
get a reply within a week, and a fix (or a workaround) before any
public disclosure.

## What this project does and does not promise

Agent Gateway is a **policy enforcement point**, not a sandbox. It
controls which tools an agent may call, with what arguments, and
under whose approval — and it logs everything in a tamper-evident
chain. It does **not**:

- stop an agent from calling a tool the policy explicitly allows;
- inspect the *meaning* of tool arguments (only their shape and
  the conditions in the policy);
- protect the upstream tool server itself (that server's own
  authentication and input validation still apply);
- guarantee that a tool's *result* is safe — that is what taint
  tracking is for, and it only applies the tighter rules after the
  first untrusted result.

The threat model is documented in `README.md` (attack benchmark
section). If you find a bypass of a control the policy claims to
enforce, that is a security issue — please report it as above.

## Supported versions

Only the latest release on `main` is supported with security fixes.
