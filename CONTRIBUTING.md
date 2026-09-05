# Contributing

Bug reports and PRs welcome. This is a small project — no CLA, no style bikeshedding.

## Local development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env      # SECRET_KEY and ADMIN_PASSWORD can be anything locally
export DATA_DIR=./data SECRET_KEY=dev ADMIN_PASSWORD=dev TZ=America/Chicago
uvicorn app.main:app --reload
```

`http://localhost:8000`. SQLite lands in `./data`.

## Tests

```bash
ruff check .
pytest -q
```

The suite runs the real app against a fake Jamf Pro (`tests/mock_jamf.py`) — an
HTTP server that mimics the endpoints this tool uses, including Jamf's habit of
serving Classic API JSON as `text/plain;charset=utf-8`. No Jamf tenant needed,
and nothing touches a real device.

If you're fixing a bug in how this talks to Jamf, teach the mock the behaviour
first and watch the test fail. That's how the 1.0.1 discovery bug was caught:
the mock was too polite about its content types, so the bug was invisible.

## Adding an action

1. Add an entry to `ACTIONS` in `app/actions.py` — `label` plus the `needs` list
   that decides which pickers the form shows.
2. Handle it in `run_action()`.
3. If it needs a picker that doesn't exist yet, add a `data-need` block in
   `templates/job_form.html` and a case in `applyNeeds()`.
4. Add a test in `tests/test_app.py` that saves the job and runs it.

Anything that writes to Jamf should read current state, modify, then write —
see the scope handlers — so a scheduled job never clobbers unrelated config.

## Things to be careful about

- **Destructive commands.** `EraseDevice` and `DeviceLock` are in here. Any
  change to command dispatch needs a test proving the right device IDs go to
  the right endpoint.
- **Timezones.** Everything is persisted UTC and rendered in the job's own
  timezone. `app/models.as_utc()` exists because SQLite drops `tzinfo`.
- **Credentials.** They're Fernet-encrypted under `SECRET_KEY`. Don't add
  logging that could print a secret or a token.
