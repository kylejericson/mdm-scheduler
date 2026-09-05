## What this changes

<!-- One or two sentences. -->

## Checklist

- [ ] `ruff check .` and `pytest -q` pass
- [ ] New behaviour has a test (the fake MDMs in `tests/` need no real tenant)
- [ ] Anything that writes to an MDM was verified against a real tenant, or is
      called out below as untested
- [ ] Vendor API calls come from the official reference, with the endpoint noted
      in a comment or the changelog
- [ ] No credentials, tokens or PINs in code, tests, logs or fixtures
