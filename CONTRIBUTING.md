# Contributing

Thanks for your interest. This is a one-person side project maintained in spare time, so
please expect replies to take a while — but everything gets looked at eventually.

## How you can help

- **Report a bug or a wrong verdict.** Open an issue with the site or URL, the technology
  and version shown, what you expected, and the output of `wappacvelyze scan --format json`
  if you used the CLI. Wrong verdicts usually trace back to a fingerprint, a CPE alias, or
  a data source, and the JSON makes that quick to spot.
- **Fix something.** Pull requests for bug fixes, fingerprint and data-source improvements,
  tests and docs are welcome. Keep each PR to one change and say what it does in the
  description.
- **Fork it.** The code is MIT licensed — fork, adapt, ship your own build. If you improve
  something generally useful, a PR back is appreciated but never expected.

## Before you open a pull request

```sh
make test               # Go: go test ./...
make vet                # Go: go vet ./...
cd extension
npm test                # extension: vitest
npm run typecheck       # tsc --noEmit
npm run lint            # oxlint
```

CI runs the same checks. `gofmt` and `npm run fmt` (oxfmt) take care of formatting.

For extension changes, load `extension/dist` unpacked in a Chromium browser and check the
popup on a real site; `make extension` builds it.

## What to know about the code

- `detect/` and `extension/src/lib/detect.ts` wrap the same fingerprint database and must
  agree; `cve/` and `extension/src/lib/{db,classify,nvd}.ts` implement the same verdict
  pipeline in Go and TypeScript. A behaviour change usually lands in both.
- The vulnerability database is built by `cmd/wappacvelyze-db` and published by a daily
  workflow; the schema lives in `db/schema.go` and `extension/src/lib/db.ts`. Bump
  `SchemaVersion` in both when you change it incompatibly.
- Generated data (fingerprints, logos, the database) is never committed.

## Conduct

Be kind and assume good intent. Reports that are clear and reproducible get fixed fastest.
