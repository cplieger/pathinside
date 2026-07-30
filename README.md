# pathinside

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/pathinside.svg)](https://pkg.go.dev/github.com/cplieger/pathinside)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/pathinside)](https://github.com/cplieger/pathinside/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/pathinside/badges/coverage.json)](https://github.com/cplieger/pathinside/actions/workflows/coverage.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13882/badge)](https://www.bestpractices.dev/projects/13882)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/pathinside/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/pathinside)

> Is this cleaned path the same as this root, or beneath it? Was it written plainly at all? Two lexical path questions, spelled correctly

Every program that hands an externally-influenced path to the filesystem needs the containment answer somewhere: an archive entry name before extraction, a filesystem-event path before it extends a watch set, a request-supplied path before it is read or deleted, a path read back out of a log the program wrote earlier. The rule is four lines. The shapes that are nearly it are wrong in ways a passing test does not show:

- `strings.HasPrefix(target, root)` accepts a **sibling** whose name merely starts with the root's. With root `/srv/data`, the path `/srv/data-evil` passes and is not inside anything. Appending a separator to the root before the prefix test fixes that case and breaks another: it now rejects the root itself, and it answers differently on unclean input than its author's examples suggest.
- `filepath.Rel` plus a leading-`..` **string** test refuses the legitimate name `..extras/movie.mkv`, whose first segment happens to begin with two dots.

The rule that is right on both counts is `filepath.Rel` followed by a **separator-precise** test of the result: the relative path escapes exactly when it is `..` or begins with `..` followed by a separator. `Rel` is what defeats the prefix sibling — `Rel("/srv/data", "/srv/data-evil")` is `../data-evil`, so the target is reached by _leaving_ the root, which is what "outside" means — and the separator is what keeps `..extras` a name rather than a traversal.

Standard library only, zero dependencies.

## Two axes

**Containment** needs a root and asks where a path points — `Inside`, `RelEscapes`. **Hygiene** needs no root and asks how a path is written — `HasDotDot`, `IsCanonical`. Pick by whether you have a root: an archive entry about to be joined onto an extraction directory is containment; a credential path, a backup destination or a cache directory read from a config file or a flag is hygiene.

The axes are separate because they disagree, and they disagree on the inputs that matter. Containment cleans first, so a traversal that normalizes away is not an escape: `/run/secrets/../../etc/shadow` cleans to `/etc/shadow`, leaves no root, and `RelEscapes` reports `false`. Hygiene never cleans, so `HasDotDot` reports `true` — a legitimate credential path was not written with two traversals in it. Answering a hygiene question with a containment function is therefore not a near-miss but an inversion: the refusal becomes an acceptance, at whatever boundary the caller was guarding.

## Install

```sh
go get github.com/cplieger/pathinside@latest
```

## Usage

### Containment

```go
if !pathinside.Inside(root, event.Name) {
    slog.Warn("refusing to extend the watch set outside the watched root", "path", event.Name, "root", root)
    return
}
```

Both arguments are cleaned (`filepath.Rel` cleans base and target itself), so `/a/b/`, `/a/./b` and `/a/x/../b` are all the same root, and a caller that pre-cleans gets the same answer as one that does not. The root itself is inside: `Inside(root, root)` is true, because the tree includes its own root (a scan that starts there, a watch registered on it, an archive's `./` entry). A pair that cannot be compared lexically — an absolute target against a relative root, or two Windows volumes — is refused rather than guessed.

### Validating a relative name

`RelEscapes` is the second half on its own, for the moment _before_ a name is joined onto anything:

```go
switch {
case name == "":
    return fmt.Errorf("archive holds an entry with an empty name")
case filepath.IsAbs(name):
    return fmt.Errorf("archive entry %q is an absolute path", name)
case pathinside.RelEscapes(name):
    return fmt.Errorf("archive entry %q escapes the extraction directory", name)
}
```

It also serves a caller that already holds a `filepath.Rel` result it needs for other work, so the containment question costs no second `Rel`:

```go
rel, err := filepath.Rel(root, path)
if err != nil || pathinside.RelEscapes(rel) {
    return false
}
_, err = rootDir.Stat(rel) // os.Root-relative, symlink-safe
return err == nil
```

`RelEscapes` says nothing about whether the name is relative at all: `/etc/passwd` cleans to itself, is not `..`, and does not begin with `../`, so **the caller rejects absoluteness**. That refusal is not cosmetic — `filepath.Clean` clamps a traversal at the filesystem root, so `/..` cleans to `/` and is accepted here, while `filepath.Join` re-attaches the unclamped traversal to a relative base: `filepath.Join("data", "/..")` is `.`, above the root.

### Syntactic hygiene

No root and no cleaning: the value is judged as written, because a human was supposed to spell it plainly. The composed rule is the OR of both predicates:

```go
if !pathinside.IsCanonical(dir) || pathinside.HasDotDot(dir) {
    return fmt.Errorf("dump directory %q must be written plainly, without %q", dir, "..")
}
```

Both halves are needed, because neither implies the other. `..` and `../dumps` are perfectly canonical, so canonicality alone accepts a leading traversal; and `/dumps/../etc` traverses while `/dumps/a..b` and `key..v2` are ordinary names, so the traversal test is component-precise rather than a substring search. Canonicality is also what **bounds** the disagreement between the axes: `filepath.Clean` leaves `..` components only at the front of a relative path, so on canonical input `HasDotDot` and `RelEscapes` always agree, and they diverge only on unclean input — the input an attacker supplies.

## API

| Symbol | Contract |
| --- | --- |
| `Inside(root, target string) bool` | Reports whether target is root itself or a path beneath it. Both arguments are cleaned. Lexical: no symlink resolution. A pair `filepath.Rel` cannot compare (absolute against relative, differing Windows volumes) is false. |
| `RelEscapes(rel string) bool` | Reports whether a relative name leaves the root it is relative to: it IS `..` or begins with `..` plus a separator. `rel` is cleaned first, so a buried traversal (`a/../../etc`) is caught. Says nothing about absoluteness — the caller rejects that. |
| `HasDotDot(p string) bool` | Reports whether p holds a `..` **component**, examined as written. p is **not** cleaned, so a traversal that would normalize away is still caught. Components come from `filepath.ToSlash(p)` split on `/`, so a backslash counts only on Windows, where it is a separator. `...`, `..extras` and `key..v2` are names, not traversals. |
| `IsCanonical(p string) bool` | Reports whether p is already in `filepath.Clean` form. Refuses a trailing or doubled separator, a `.` component, a buried traversal, and the empty string. `..` and `../dumps` are canonical — canonicality is not hygiene, so pair it with `HasDotDot`. |

## Lexical, not enforced

All four functions compare **names** and resolve nothing. A symlink inside the root pointing anywhere at all is still lexically inside it, and a path that passes can be swapped between the check and the syscall.

That is the right answer for a name-level decision (_is this path mine to handle_) and the wrong one for an access-level decision (_may this open succeed_). Callers that open, read, write, rename or remove through the path want kernel-enforced confinement — [`os.Root`](https://pkg.go.dev/os#Root) via `os.OpenRoot` / `os.OpenInRoot`, which refuses to traverse a symlink out of the tree and closes the TOCTOU window a lexical check cannot see. The two compose: the cheap lexical gate gives an early, quiet refusal and a clear operator message; the confined handle makes the operation itself safe.

## Name validation is stricter than containment

The two containment functions do not always agree, and the disagreement is deliberate. A name that walks out of the root and back into a directory that happens to share the root's name — `../a` under root `a` — is refused by `RelEscapes` while its joined result (the root itself) is `Inside`. `RelEscapes` judges the shape of a **name**; `Inside` judges the location of a **result**. A caller validating an untrusted name wants the strict answer, because a legitimate name has no business leaving. Fusing the two would pick one answer for both callers.

## Unsupported by Design

| Feature | Rationale |
| --- | --- |
| Symlink resolution | It would turn a pure string predicate into a filesystem call with its own error mode, and still lose the TOCTOU race. `os.Root` is the answer, and it is in the standard library. |
| A `SafeJoin`-style "validate and join" helper | The refusals a caller owes its user are the caller's: an empty name, an absolute name, and a traversal deserve distinct messages, and a helper that returns one error for all three makes them indistinguishable. Compose `RelEscapes` with `filepath.IsAbs` and `filepath.Join`. |
| A variant that excludes the root | The one caller that needs it needs a different rule (it rejects equality _and_ wants its own error), and hiding that behind a flag would let a caller pick the wrong containment semantics with one boolean. Test for equality explicitly. |
| Case-insensitive or Unicode-normalizing comparison | Case folding and normalization are filesystem properties, not path properties, and getting them wrong in either direction is a security bug. A caller on a case-insensitive filesystem normalizes both paths itself, with its own knowledge of the mount. |

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
