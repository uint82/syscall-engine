# Contributing

## Branches

Branch from `main` and prefix the branch name with the type of change:

- `feat/short-description`
- `fix/short-description`
- `docs/short-description`

Keep one feature or fix per branch.

## Commits

Commits follow Conventional Commits. A commit message is a single subject line with no description body.

Format:

```
type(scope): subject
```

Types:

- `feat`: a new capability
- `fix`: a bug fix
- `impr`: an improvement to existing behavior
- `refactor`: a change that neither fixes a bug nor adds a capability
- `perf`: a performance change
- `test`: test only changes
- `docs`: documentation only changes
- `ci`: continuous integration changes
- `build`: build system or dependency changes
- `chore`: maintenance that fits nowhere else

Scopes:

- `core`: portable PE, SSN, and stub code
- `engine`: Windows engine and loader
- `ntdll`: fresh ntdll mapping
- `tests`: test suites
- `docs`: documentation
- `ci`: workflows

Rules:

- Use the imperative mood: `add`, not `added`
- Lowercase subject, no trailing period
- Keep the subject at 72 characters or fewer
- One logical change per commit
- No description body

Examples:

```
feat(ntdll): map KnownDlls ntdll as a clean image source
fix(engine): keep the gadget inside the live module
docs: document conventional commits
```

## Pull requests

- Keep each pull request focused on one feature or fix
- Run `ctest --test-dir build --output-on-failure` locally before pushing
- Make sure both the Linux and Windows jobs pass in CI
- Use a conventional commit style title for the pull request

## Releases

- Version tags use `vMAJOR.MINOR.PATCH`
- Tagging `main` runs the release workflow, which tests both platforms, builds the loader, and publishes the binary with a SHA-256 checksum
- Prerelease suffixes such as `-rc.1` mark the release as a prerelease
