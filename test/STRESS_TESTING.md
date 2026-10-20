# Local stress and regression tests

Run from the repository root after `npm ci` and installing both bundled Python
packages into a disposable virtual environment:

```text
python -m pip install ./resources/python ./resources/gateway
npm test
python -m unittest discover -s resources/python/tests -v
python -m unittest discover -s resources/gateway/tests -v
node test/runtime-smoke.mjs
```

These tests use temporary directories, dummy credentials, loopback servers and
fixture responses. They make no paid inference requests. The runtime smoke test
downloads dependencies and installs a disposable runtime; it does not modify the
user's vault. CI runs the same checks on Windows, macOS and Linux.

The stress regressions cover:

- 24 child gateway launches in three concurrent bursts of eight, checking
  independent ports and session directories, health responses and shutdown.
- 360 mixed HTTP requests with eight workers: 240 successful requests across
  Chat Completions, Anthropic Messages and Responses, plus 120 malformed requests.
  All 120 streaming requests must close their upstream fixture.
- Saturating all 16 connection slots, rejecting excess work and recovering after
  the active requests finish. Separate admission tests cover slow uploads and
  invalid transfer framing.
- Three bursts of 16 requests against cold/expired proof caches: each burst must
  perform exactly one attestation verification for that model.
- 24 parallel tool calls with interleaved single-character JSON fragments,
  truncated output, missing receipts, client disconnects during headers/body,
  and upstream disconnects before stream creation.
- Windows drive paths, UNC paths, quoted spaces and trailing path separators in
  console commands. On Windows, backslashes are literal; use single or double
  quotes to group arguments. POSIX backslash escaping is unchanged.

Anthropic tool arguments are buffered until the upstream receipt is verified,
then emitted as sequential content blocks. Text and thinking still stream as
they arrive. This avoids closing a tool block before later parallel fragments
arrive; clients receive tool arguments later than before.

This is repeatable coverage of these failure modes, not an exhaustive fuzzing
campaign or a load test of the hosted billing and confidential inference services.
