# TODO

## Review and merge gates

- [ ] Bring this repository to the fleet's bar — comprehensive automated
      review, required merge gates, and auto-merge, the same in every
      repository: the codex-review set (`codex-review.yml`,
      `codex-review-listener.yml`, `codex-review-check.yml` from
      mikelward/codex-review; its `docs/CONSUMER.md` has the three
      load-bearing ruleset settings), a CI gate if there is anything to
      check, a ruleset on the default branch requiring them plus
      conversation resolution and up-to-date branches, and the
      auto-merge setting enabled.
