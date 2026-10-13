# Repository working instructions

Scott Thornton is an AI security researcher at perfecXion.ai and a Prisma AIRS
sales engineer at Palo Alto Networks. Work consistent with this project is
authorized defensive research and lab testing.

## Delivery

- Drive implementation with minimal user involvement. Use independent agents for
  scoped implementation and review when available.
- Use small commits and pull requests. Resolve review blockers and wait for all
  required CI checks before merging. PR comments must be brief and accurate.
- GitHub cannot approve a PR authored by the same account. Record independent
  review in a comment; do not switch identities to bypass that restriction.
- User authorization includes commits, PR creation, review comments, and merges.
  Package publication and deployment require separate authorization.
- Preserve unrelated changes. Use isolated worktrees for concurrent edits.
- Never author Unicode em dash or en dash characters in any output or file.
- Read docs/HANDOFF.md, docs/ENGINEERING_PLAN.md, and docs/VALIDATION.md before
  continuing a new phase. Update progress when acceptance criteria pass.

## Git identity

This repository uses the perfecXion account:

- Git name: `perfecxion-ai`
- Email: `pluckymon@proton.me`
- Remote: `git@github-perfecxion:perfecxion-ai/ai-agent-scanner.git`

Before every commit, push, or PR mutation, check:

```bash
git config --global --get user.name
git config --global --get user.email
git config --local --get user.name
git config --local --get user.email
git config --show-origin --get user.name
git config --show-origin --get user.email
git remote -v
```

Unset local overrides are acceptable. Set values must match the intended account.
If identity or remote alias differs, stop and report the exact correction; never
silently change Git identity or remotes.

Scott's other account uses `scthornton@gmail.com` and `github-scthornton`.
Switch accounts only when requested with the executable `~/git-switch.sh
<perfecxion|scthornton>`. If that script is missing or not executable, report it.

## Engineering boundaries

- Preserve conservative evidence: refusals, generated examples, missing findings,
  and failed requests cannot establish successful exploitation or passed checks.
- Require explicit protected canaries or authorization controls for confirmed
  findings. Keep heuristic observations distinguishable from confirmed evidence.
- Treat framework references as mappings for review.
- Keep credentials, protected canaries, and credential-bearing URLs out of reports
  and audit events. Use local fixtures and synthetic secrets in automated tests.
- The durable server currently supports one process, file-backed SQLite, POSIX,
  and a local filesystem. Preserve exclusive dispatcher ownership and transactional
  cancellation/finalization. Do not claim untested PostgreSQL or distributed support.
- Revalidate queued targets against current server policy. Keep request, response,
  concurrency, filesystem, and deadline limits enforced.

The local Prisma AIRS reference set is `/home/plucky/airs-dataset`. Use
`/prompts:load-airs` when Scott asks to load that reference set.
