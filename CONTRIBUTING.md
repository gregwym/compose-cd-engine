# Contributing

Use Python 3.12+; run the README checks before a PR. Add meaningful tests for
trust-boundary or state/rollback changes. Keep real deployments out of fixtures.
Do not add credentials or production dependencies to Actions. Pull requests run
read-only checks and native image smoke tests, never image publication/deployment.

The engine protocol is v1. Changes to policy/candidate/receipt shape, permissions
or snapshot semantics need compatibility and rollback notes. Releases are explicit
maintainer actions. An engine release does not implicitly authorize upgrading any
production deployment. Contributions are provided under the MIT license.
