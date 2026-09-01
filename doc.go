// Package pathinside judges path NAMES, along two axes that must not be fused.
//
// CONTAINMENT needs a root and asks where a path points: is this cleaned target
// the same as this root, or beneath it? [Root.Contains] and [RelEscapes] answer
// it; see [Root.Contains] for why a separator-precise filepath.Rel test beats
// both strings.HasPrefix and a leading-".." string test, and why the root is a
// distinct type rather than a second same-typed parameter.
//
// SYNTACTIC HYGIENE needs no root and asks how a path is written: does it spell
// a traversal, is it in cleaned form? [HasDotDot] and [IsCanonical] answer that;
// see [HasDotDot] for the separator rule and why a substring test is wrong.
//
// The axes disagree on unclean input, which is precisely what an attacker
// supplies: containment cleans first, so "/run/secrets/../../etc/shadow" cleans
// to "/etc/shadow" and passes; hygiene never cleans, so the same path fails.
// Answering a hygiene question with a containment function is therefore not a
// near-miss but an inversion — a refusal becomes an acceptance. Canonicality
// bounds the disagreement: filepath.Clean leaves ".." only at the front of a
// relative path, so on canonical input the two axes always agree.
//
// All four predicates are LEXICAL: they compare and inspect names and resolve
// nothing, so a symlink inside the root is still lexically inside it. That is
// the right answer for a name-level decision and the wrong one for an
// access-level one; callers that open, read, write, rename or remove through
// the path also want kernel-enforced confinement (os.Root's OpenRoot /
// OpenInRoot).
//
// Lexical does not mean byte-exact everywhere: [Root.Contains] inherits
// filepath.Rel's platform case-fold rule (see its doc comment). The hygiene
// predicates are immune on every platform — they compare against the literal
// "..", which has no case-fold partners.
//
// Standard library only, zero dependencies.
package pathinside
