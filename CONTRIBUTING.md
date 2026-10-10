# Contributing

- Run the tests: `python -m unittest discover -s tests -v`.
- A new rule needs: an ID in `dave/rules.py` with English and French texts, a test fixture, and a test.
- Rules must be **sourced**: link the documentation or advisory that justifies the check in your pull request.
  No guessed defaults (for example, only flag "runs as root" for images verified to do so).

## Licensing of contributions
Dave is dual-licensed by its author (AGPL for everyone, separate terms for Dave Pro). Contributions are accepted
under a Contributor License Agreement that allows this; you keep the copyright of your work.
