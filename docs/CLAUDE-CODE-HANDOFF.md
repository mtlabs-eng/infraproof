# Claude Code handoff

## Session discipline

Use one implementation session and a fresh independent review session per milestone. Do not activate multiple milestones in one prompt.

## Planning prompt

```text
Read CLAUDE.md and every document referenced by it.

The active milestone is docs/milestones/01-evidence-bundle.md.

Do not modify files yet. Inspect the repository and produce an implementation plan for this milestone only.

For every proposed step, identify:
- files affected;
- public interfaces;
- tests written first;
- failure cases;
- corresponding acceptance criterion.

Flag contradictions or ambiguities instead of making product decisions. Do not design or implement future milestones.
```

Start with:

```sh
claude --permission-mode plan
```

## Implementation prompt

```text
The implementation plan for the active milestone is approved.

Implement only that milestone. Write acceptance tests first and run them to observe the expected failures. Then implement the smallest general solution that satisfies them.

Do not hard-code fixture-specific answers, weaken tests, introduce cloud access, or implement future milestones. Never run terraform apply or terraform destroy.

Run formatting, static analysis, and the complete test suite before finishing. Report:
1. acceptance criteria satisfied;
2. files changed;
3. verification commands and results;
4. unresolved limitations.
```

## Independent review prompt

```text
Act as an independent reviewer. Do not edit files.

Read CLAUDE.md, the active milestone, and the implementation diff. Verify every acceptance criterion, with special attention to sensitive and unknown values, deterministic output, provider-neutral boundaries, and fixture-specific hard-coding.

Run the complete test suite. Report only reproducible findings with severity and file locations. If there are no findings, state that explicitly and list the verification performed.
```

## Completion gate

A milestone is complete only when:

- all acceptance criteria are demonstrated;
- tests and static analysis pass;
- an independent review has no unresolved material findings;
- documentation reflects the implemented behavior;
- the next milestone has not leaked into the implementation.
