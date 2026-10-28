# Contributing

- [docs/design.md](docs/design.md) is the spec. Change it in the same pull request as
  any behaviour change.
- Keep the three-container shape and the single database. New state belongs in the
  gateway's SQLite; the runner stays stateless.
- Anything that touches project files must keep Container Manager compatibility
  (identity labels, in-place writes, `.env` semantics). Add a real-Docker test in
  `tests/test_runner_docker.py`.
- Run `CD_DOCKER_TESTS=1 PYTHONPATH=.:tests python3 -m unittest discover -s tests` before
  opening a pull request. Contributions are provided under the MIT license.
