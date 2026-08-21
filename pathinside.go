package pathinside

import (
	"path/filepath"
	"strings"
)

// Root is the tree a containment question is asked against — the sticky side
// of the comparison. Construct it ONCE, where the confinement boundary is
// decided (a watch root, an extraction directory, a configured data
// directory), and let targets flow past it: the misuse-resistance is bought
// at the construction site, not by the type. An inline conversion at the call
// site — pathinside.Root(x).Contains(y) — still compiles with x and y
// transposed, which is the v1 hazard in new spelling; a Root held in a named
// field or variable is what makes a transposition visible. (Most call sites
// have a boundary to construct at; a site whose root varies per item while
// the TARGET is fixed is the inverted case — keep the inline form there and
// let the variable names carry the direction.)
//
// A Root is constructed by plain conversion: pathinside.Root("/srv/data"). The
// conversion IS the construction — no constructor, no validation, no hidden
// state, matching the package's pure-function character. Nothing is normalized
// at conversion time either: cleaning happens where it always did, inside
// filepath.Rel at judgment time, so Root("/a/b/"), Root("/a/./b") and
// Root("/a/b") judge every target identically.
//
// They cost differently, though, and a long-lived Root is where that shows.
// Because the cleaning happens per judgment rather than once at conversion, a
// root whose spelling forces filepath.Clean to REWRITE it pays for that rewrite
// on every target it judges, for as long as the value lives. Measured: a clean
// root and a trailing-separator root judge a target for zero allocations, while
// Root("/srv/./data") costs two on every call — a dot component makes Clean
// build a new string, where a trailing separator only truncates and returns a
// substring. Prefer storing a filepath.Clean'd root when the value comes from
// configuration and will judge many paths; the answers are identical either
// way, so this is a cost note and never a correctness one.
//
// The zero value Root("") CONTAINS NOTHING: every Contains answer is false.
// An empty root is almost always an unset field or a missed configuration
// value, and the fail-open alternative — filepath.Rel cleans "" to ".",
// silently confining to the current working directory, a boundary nobody
// chose — is the direction a containment bug must not take. A caller that
// genuinely wants cwd-relative containment writes Root(".") and says so.
type Root string

// Contains reports whether target names the root itself or a path beneath it. It
// is the containment predicate a caller reaches for before letting an
// externally-influenced path reach the filesystem: an archive entry name, a
// filesystem-event path, a request-supplied file path, a path read back out of
// a log the program itself wrote.
//
// The root and the target are both cleaned: filepath.Rel cleans base and target
// itself, so a caller passing filepath.Clean'd paths and one passing raw ones
// get the same answer, and "/a/b/" , "/a/./b" and "/a/x/../b" are all the same
// root. Nothing else is normalized — no symlink resolution, no Unicode
// normalization, no conversion between absolute and relative.
//
// CASE IS THE PLATFORM'S RULE, and it is the one place this method is not
// byte-exact. filepath.Rel compares path components case-INSENSITIVELY on
// Windows and byte-exactly on Unix and Plan 9, so Root("/srv/Data").Contains(
// "/srv/data/x") is false on Linux and true on Windows. Rel's own documentation
// does not say so, which is why it is said here: a containment boundary cannot
// afford to inherit a comparison rule it does not know about. This package
// neither adds that folding nor removes it — reimplementing Rel to force
// byte-exactness would refuse a Windows caller the very path its filesystem
// resolves to the root.
//
// Two consequences follow, and they point in opposite directions. On Windows the
// folding is the TOOLCHAIN's simple Unicode case folding, not the volume's own
// uppercase table, so the two can disagree — and a fold relation that grows
// makes containment MORE permissive, never less, which is the direction a
// containment bug takes: a target in a sibling directory starts reading as
// inside. Go 1.27's Unicode 17 tables fold pairs Go 1.26 held distinct
// (U+FB05/U+FB06 and the Greek U+0390/U+1FD3, U+03B0/U+1FE3 among them), so
// Windows containment loosened by exactly those names. The other direction is
// the reassuring one: [RelEscapes], [HasDotDot] and [IsCanonical] compare
// against the literal "..", whose runes have no case-fold partners at all, so no
// fold table on any platform can turn a name into a traversal or a traversal
// into a name.
//
// THE ROOT ITSELF IS CONTAINED. Root(p).Contains(p) is true for every non-empty p, because the
// question this predicate answers is "may this path be treated as part of the
// tree rooted at root", and the tree includes its own root: a scan that starts
// at root, a watch registered on root, an archive's "./" entry. A caller that
// must EXCLUDE the root (an operation that would rewrite or delete the tree's
// own directory when handed an empty relative name) needs a second, explicit
// test of its own — do not read a false from this method as "not equal to
// root".
//
// The comparison is LEXICAL, and that is the whole contract: it says nothing
// about what the two paths resolve to. A symlink at root/link pointing at /etc
// makes root/link/passwd lexically inside root, and this method reports it as
// such. Lexical containment is the right answer for a NAME-level decision (is
// this name mine to handle) and the wrong one for an ACCESS-level decision (may
// this open succeed). A caller that opens, reads, writes, renames or removes
// through the path needs kernel-enforced confinement — os.Root (os.OpenRoot,
// os.OpenInRoot), which refuses to traverse a symlink out of the tree and
// closes the TOCTOU window this predicate cannot see. Use both when both
// questions apply: the cheap lexical gate first, the confined handle for the
// operation.
//
// Two paths that cannot be compared lexically are refused rather than guessed:
// an absolute target against a relative root (or the reverse), and on Windows
// two different volumes. filepath.Rel reports those as an error, and this
// method answers false, so an unanswerable comparison never reads as
// containment.
func (r Root) Contains(target string) bool {
	if r == "" {
		return false
	}
	rel, err := filepath.Rel(string(r), target)
	if err != nil {
		return false
	}
	return !RelEscapes(rel)
}

// RelEscapes reports whether rel, read as a path relative to some root, leaves
// that root: it IS ".." or it begins with ".." followed by a separator.
//
// It is deliberately a separate function from [Root.Contains], not folded into
// it: the two answer different questions, and fusing them would force every
// caller to buy both. Root.Contains asks whether one path lies within another.
// RelEscapes asks whether a relative NAME is well-formed for use under a root —
// which a caller must ask BEFORE it joins the name onto anything (an archive
// entry name, a configured sub-path), and which a caller holding a filepath.Rel
// result it needs for other work (an os.Root-relative Stat or Remove) can ask
// without paying for a second Rel. It takes the relative name alone — no root
// and no second path — so there is no pair to swap and no [Root] to construct.
//
// rel is cleaned first, so an uncleaned name whose traversal is buried
// mid-string ("a/../../etc") is still caught. A relative name whose result is
// the root itself (".", or the empty string, which cleans to ".") does not
// escape.
//
// Cleaning is also what this function cannot see past, and that is the boundary
// between this package's two axes. A traversal that NORMALIZES AWAY is not an
// escape: "/run/secrets/../../etc/shadow" cleans to "/etc/shadow", leaves no
// root, and is reported false here. A caller whose question is instead whether a
// path was WRITTEN with traversal in it at all — a config-supplied credential
// path, a backup destination, any value a human was supposed to spell plainly —
// is asking [HasDotDot], and reaching for RelEscapes there turns a deliberate
// refusal into an acceptance.
//
// This is a NAME rule, and it is deliberately stricter than [Root.Contains]'s
// locational one: a name that walks out of the root and back into a directory
// that happens to share the root's name ("../a" under root "a") is refused here
// while the joined result — the root itself — is inside. A caller validating an
// untrusted name wants the strict answer, because a legitimate name has no
// business leaving; a caller classifying a path it was handed wants Root.Contains.
// Fusing the two would silently pick one of those answers for both callers.
//
// The test is separator-precise, and that precision is the reason this rule is
// worth centralizing. A leading-".." STRING prefix test would refuse the
// perfectly legitimate name "..extras/movie.mkv", whose first segment merely
// begins with two dots. Requiring the separator (or an exact "..") splits the
// two cases apart: "../x" escapes, "..extras/x" does not.
//
// RelEscapes says nothing about whether rel is relative at all. An absolute
// path does not "escape" by this test — "/etc/passwd" cleans to itself, is not
// "..", and does not begin with "../" — so a caller validating an untrusted
// name must reject absolute paths separately (filepath.IsAbs, plus a leading
// separator check where a foreign path syntax is in play). That refusal is not
// cosmetic: filepath.Clean CLAMPS a traversal at the filesystem root, so "/.."
// cleans to "/" and is accepted here, while filepath.Join re-attaches the
// unclamped traversal to a relative base — filepath.Join("data", "/..") is ".",
// which is above "data". An absolute name is the caller's to refuse, on the
// grounds that a legitimate relative name was not absolute in the first place.
func RelEscapes(rel string) bool {
	rel = filepath.Clean(rel)
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// HasDotDot reports whether p contains a ".." path COMPONENT, examined AS
// WRITTEN. It is this package's second axis — syntactic hygiene — and it takes
// no root, because it asks nothing about where p points: only whether the path a
// caller was handed spells a traversal at all.
//
// p is NOT cleaned, and that is the whole of the difference from [RelEscapes].
// The two give OPPOSITE answers on exactly the inputs that matter:
// "/run/secrets/../../etc/shadow" cleans to "/etc/shadow", which leaves no root,
// so RelEscapes reports false — while this function reports true, because the
// traversal is written. Reach for [RelEscapes] when the question is "after
// normalization, does this name leave its root": an archive entry about to be
// joined, a configured sub-path resolved against a base. Reach for this function
// when the question is "was I handed a path with traversal in it": a
// config-supplied credential path, a backup destination, a value a human was
// supposed to spell plainly. Such a path is not suspicious because of where it
// resolves — it is suspicious because a legitimate one would not have been
// written that way — and answering that question with RelEscapes converts a
// deliberate refusal into an acceptance.
//
// The components are taken from filepath.ToSlash(p) split on "/", and that
// choice is the reason this rule is worth centralizing instead of hand-rolling
// per call site. ToSlash rewrites "\" to "/" ONLY on Windows, which is exactly
// the platform rule: on Unix a backslash is a legal filename byte, so `a\..\b`
// is ONE component whose name happens to contain dots and must NOT read as
// traversal; on Windows it IS a separator, so the same string is three
// components and must. Every shorter spelling is wrong somewhere — a split on
// both characters refuses a legal Unix filename, a split on filepath.Separator
// alone misses the Windows traversal, and strings.Contains(p, "..") is wrong on
// every platform at once, refusing ordinary names like "key..v2" and
// "/dumps/a..b" whose only sin is two adjacent dots.
//
// Only an exact ".." component counts. "..." is a directory name, so are
// "..extras" and "a..b": containing or beginning with two dots is not
// traversing. The empty string has no components and is false. ".." alone is
// true, and a ".." anywhere in the path is true — first component, last, or
// buried in the middle, which is the case cleaning would have hidden.
//
// HasDotDot judges nothing else. It says nothing about absoluteness (the
// caller's refusal, as with RelEscapes), nothing about whether p is otherwise
// cleanly written (pair it with [IsCanonical] when unclean spellings must be
// refused too), and nothing about what p resolves to — a symlink component is
// invisible to it, the same lexical limit the rest of this package carries.
func HasDotDot(p string) bool {
	for component := range strings.SplitSeq(filepath.ToSlash(p), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

// IsCanonical reports whether p is already in filepath.Clean form — cleaning it
// would change nothing. It is the other half of the hygiene axis, and it needs
// no root either.
//
// It exists because "does this path resolve somewhere acceptable" and "is this
// path written plainly" are different questions, and a caller validating a
// human-written value — a config field, a CLI flag — usually wants the second.
// Refusing a non-canonical path refuses in one test the whole class of spellings
// that a later normalization would silently rewrite: a trailing separator, a
// doubled separator, a "." component, a traversal buried mid-path. The caller
// gets a refusal it can explain ("write the path plainly") instead of accepting
// one string and operating on another.
//
// Canonicality is NOT hygiene, and that is why this is a separate predicate
// rather than a stricter [HasDotDot]: ".." and "../dumps" are perfectly
// canonical, so a canonicality test alone accepts a leading traversal. The
// composed rule a validating caller wants is the OR of both,
// !IsCanonical(p) || HasDotDot(p), which refuses a path that is either unclean
// or traversing.
//
// Canonicality is also what bounds the disagreement between the two axes. Clean
// leaves ".." components only at the FRONT of a relative path, so a canonical
// path containing one escapes by [RelEscapes] too: on canonical input the axes
// always agree, and they diverge only on unclean input — which is precisely the
// input an attacker supplies and a config file rarely holds by accident.
//
// The test is a string identity against filepath.Clean, so it inherits Clean's
// platform rules. The empty string is not canonical (it cleans to "."), and on
// Windows a slash-written path is not canonical either, because Clean rewrites
// separators there ("a/b" cleans to `a\b`). A caller that means to accept
// slash-written input on Windows converts with filepath.FromSlash before
// testing, not after.
func IsCanonical(p string) bool {
	return p == filepath.Clean(p)
}
