# Contributing to Comot

Thanks for helping. Comot handles consent for sensitive voice data, so a few
rules are firmer than usual.

## Set up

```bash
uv sync
uv run pytest
uv run comot demo
```

## Ground rules

- **Withdrawal must stay easy and must reach every copy.** A change that makes
  withdrawal harder, or lets a copy slip past it, will not be merged.
- **Never promise more than the system can prove.** Receipt and consent wording
  must not claim erasure from a trained model.
- **Silence is no.** No choice is ever defaulted to yes.
- **No personal data in the core.** The consent store and audit log hold
  pseudonymous ids and hashes only: no names, phone numbers or recording
  content.
- **Test the rule, not just the path.** New behaviour needs a test that fails
  without it. Tests for consent and withdrawal rules should assert the
  restriction, not only the happy case.
- **Consent scripts come from the community.** Do not add a signed-off script or
  audio from your own translation. Drafts are welcome as clearly marked drafts.

## Pull requests

Keep them small and say what rule or behaviour changes. Run `uv run pytest`
before pushing.

## Security

If you find a way to read, alter or bypass consent or audit data, please report
it privately to the maintainers instead of opening a public issue.
