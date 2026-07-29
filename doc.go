// Package pathinside judges path NAMES, along two axes that must not be fused.
//
// CONTAINMENT needs a root and asks where a path points: is this cleaned target
// the same as this root, or beneath it? [Inside] and [RelEscapes] answer it.
//
// SYNTACTIC HYGIENE needs no root and asks how a path is written: does it spell
// a traversal, is it in cleaned form? [HasDotDot] and [IsCanonical] answer that.
//
// The axes are separate because they disagree, and they disagree on the inputs
// that matter. Containment cleans first, so a traversal that normalizes away is
// not an escape — "/run/secrets/../../etc/shadow" cleans to "/etc/shadow", which
// leaves no root and passes. Hygiene never cleans, so the same path fails, on the
// grounds that a legitimate credential path was not written with two traversals
// in it. Answering a hygiene question with a containment function is therefore
// not a near-miss but an inversion: the refusal becomes an acceptance, at
// whatever boundary the caller was guarding.
//
// # Containment
//
// Every program that hands an externally-influenced path to the filesystem needs
// that answer somewhere — an archive entry name before extraction, a
// filesystem-event path before it extends a watch set, a request-supplied file
// path before it is read or deleted, a path read back out of a log the program
// wrote earlier. The correct lexical rule is short, and the shapes that are
// nearly it are wrong in ways that do not show up in a passing test:
//
//   - strings.HasPrefix(target, root) accepts a SIBLING whose name merely
//     starts with the root's: with root "/srv/data", the path "/srv/data-evil"
//     passes the prefix test and is not inside anything. Appending a separator
//     to the root before the prefix test fixes that one case and introduces
//     another (it now rejects the root itself, and it answers on unclean input
//     the way its author's examples never did).
//   - filepath.Rel plus a leading-".." STRING test refuses the legitimate name
//     "..extras/movie.mkv", whose first segment happens to begin with two dots.
//
// The rule that is right on both counts is filepath.Rel followed by a
// SEPARATOR-PRECISE test of the result: the relative path escapes exactly when
// it is ".." or begins with ".." followed by a separator. Rel is what defeats
// the prefix sibling — Rel("/srv/data", "/srv/data-evil") is "../data-evil", so
// the target is reached by leaving the root, which is what "outside" means —
// and the separator is what keeps "..extras" a name rather than a traversal.
//
// [Inside] is that rule. [RelEscapes] is its second half on its own, for a
// caller that must validate a relative NAME before joining it onto anything, or
// that already holds a filepath.Rel result it needs for other work (an
// os.Root-relative Stat or Remove) and should not pay for a second Rel. Name
// validation stays a separate question from containment on purpose: the two are
// asked at different moments, and they do not always agree. RelEscapes is the
// stricter of the two — a name that leaves the root and returns to a directory
// with the same name ("../a" under root "a") is refused as a name while its
// joined result is Inside — and a caller validating an untrusted name wants that
// strictness, because a legitimate name has no business leaving. Fusing them
// would pick one answer for both callers.
//
// # Syntactic hygiene
//
// The commoner question in practice has no root at all. A credential path, a
// backup destination, a cache directory read from a config file or a flag is
// judged on its own: it was meant to be written plainly, and a traversal in it is
// a red flag whatever it resolves to. [HasDotDot] is that test — does p contain a
// ".." COMPONENT, as written, without cleaning — and [IsCanonical] is its
// companion, whether p is already in filepath.Clean form. The composed rule most
// such callers want is the OR of the two: !IsCanonical(p) || HasDotDot(p) refuses
// a path that is either unclean or traversing.
//
// Both halves are needed, because neither implies the other. ".." and "../dumps"
// are perfectly canonical, so a canonicality test alone accepts a leading
// traversal; and "/dumps/../etc" is traversing while "/dumps/a..b" and "key..v2"
// are ordinary names, so the traversal test must be component-precise rather than
// a substring search. Canonicality is what BOUNDS the disagreement between the
// axes: filepath.Clean leaves ".." components only at the front of a relative
// path, so on canonical input HasDotDot and RelEscapes always agree, and they
// diverge only on unclean input — the input an attacker supplies.
//
// The separator handling in [HasDotDot] is the part worth centralizing. It
// splits filepath.ToSlash(p) on "/", so a backslash counts as a separator only
// on Windows, where it is one: on Unix `a\..\b` is a single legal filename and
// must not read as traversal, on Windows it is three components and must. A
// hand-rolled split on both characters is wrong on Unix, a split on
// filepath.Separator alone is wrong on Windows, and strings.Contains(p, "..") is
// wrong everywhere.
//
// # Lexical, not enforced
//
// All four functions are LEXICAL. They compare and inspect names and resolve
// nothing: a symlink inside the root pointing anywhere at all is still lexically
// inside it, and a path that passes can still be swapped between the check and
// the syscall. That is the right answer for a name-level decision (is this path
// mine to handle) and the wrong one for an access-level decision (may this open
// succeed). Callers that open, read, write, rename or remove through the path
// want kernel-enforced confinement — os.Root's os.OpenRoot / os.OpenInRoot,
// which refuse to traverse a symlink out of the tree — with this package's cheap
// lexical gate in front of it where the caller also wants an early, quiet
// refusal.
//
// The root itself is inside: Inside(root, root) is true. A caller that must
// exclude it (an operation whose empty relative name would rewrite the tree's
// own directory) tests that separately; a false from Inside never means "equal
// to root".
//
// Standard library only, zero dependencies.
package pathinside
