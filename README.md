# pathcase-lab

**Find filename portability hazards before they break a checkout, sync, archive, or release.**

`pathcase` has two deliberately separate commands:

- `audit` reads a directory tree and reports Windows-invalid names and sibling names that may collide after Unicode normalization, case folding, or Windows edge trimming.
- `probe` creates disposable files in a temporary directory to measure how the *selected filesystem* actually handles six tricky name pairs. It deletes the directory afterward.

That split matters: an operating system name alone does not tell you how a particular mounted volume compares names. The static audit is a conservative portability warning, while the probe reports observed behavior on one volume. Neither command renames user files.

## Install

Requires Python 3.10 or later. Runtime dependencies: **none**.

```sh
python3 -m pip install .
pathcase --help
```

To run from a checkout without installing:

```sh
PYTHONPATH=src python3 -m pathcase_lab audit .
```

## Audit a repository

```sh
pathcase audit . --exclude 'node_modules/**' --exclude 'dist/**'
pathcase audit . --json > pathcase-report.json
```

Example finding:

```text
portable_name_collision: "docs/Readme.md", "docs/README.md" — Sibling names share the conservative NFC + casefold + Windows trim key.
```

`audit` does not follow symlinks. It always skips `.git` directories. `--exclude` matches relative POSIX paths; repeat it for more patterns. It reports scan errors instead of silently declaring the tree clean.

Checks include reserved Windows device names (including `COM¹` and `LPT²`), forbidden characters and control characters, leading ASCII spaces, trailing spaces or periods, and candidate sibling collisions. A candidate collision is a prompt to test the target filesystem; it is **not** a claim that every platform would merge those names.

## Probe a filesystem

```sh
pathcase probe --parent /path/on/the/volume
pathcase probe --parent /path/on/the/volume --json
```

`probe` tries ASCII case, composed versus decomposed Unicode, Unicode case folding, trailing period, trailing space, and leading space pairs. It uses exclusive creation (`O_EXCL`) so the second name cannot overwrite the first. Every case is isolated under a new temporary directory within the selected parent. Results are `distinct`, `collision`, or `unsupported`; stored names are included in JSON to show spelling changes.

Run the probe on each filesystem you care about: a Mac startup disk, an external disk, a Linux CI runner, or a Windows checkout may give different answers.

## JSON and exit codes

Both commands produce schema version `1` JSON with `--json`. `audit` returns `0` for no findings, `1` for findings, and `2` for invalid input or incomplete scanning. `probe` returns `0` after a completed probe and `2` when it cannot start. An `unsupported` probe case is an observed result, not a CLI failure.

```sh
pathcase audit . --json > pathcase-report.json
status=$?
if [ "$status" -eq 1 ]; then
  echo "Review portable filename findings"
fi
```

## Scope and durability

The policy key uses Unicode NFC normalization, Unicode case folding, and Windows ASCII leading/trailing name trimming. It intentionally errs on the side of review. Filesystems and APIs can apply different comparison rules, so this tool does not certify portability or model every Windows namespace, network share, or archive format. Python's Unicode database version is recorded in each report so later runs can be compared honestly.

The core problem does not depend on a vendor API or an AI model: developers will still exchange source trees and artifacts between filesystems with different naming rules in 2030. The implementation uses only the Python standard library and a versioned JSON format.

References: [Microsoft file naming rules](https://learn.microsoft.com/en-us/windows/desktop/fileio/naming-a-file), [Unicode normalization specification](https://www.unicode.org/reports/tr15/).

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Contributions that add a probe case should keep it harmless, isolated, and meaningful on multiple platforms. Please add a test and explain what the result can and cannot prove.

MIT licensed. See [LICENSE](LICENSE).
