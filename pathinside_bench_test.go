package pathinside_test

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/cplieger/pathinside/v2"
)

// This file gates the package's cost claim (a lexical judgment that allocates
// nothing) rather than just its trend: TestXxxAllocations asserts
// testing.AllocsPerRun == 0 on measured-zero input classes, so a regression
// fails at merge time; the Benchmark functions feed the weekly trend tracker.
//
// Measured findings, so a re-run is not needed to rediscover them:
//   - HasDotDot never calls filepath.Clean and is allocation-free on every
//     input class at every depth.
//   - RelEscapes and IsCanonical are allocation-free on canonical input and
//     allocate 2 when Clean must rewrite (Clean returns a substring of its
//     argument when the result is a prefix of the input).
//   - Root.Contains is allocation-free on its accept path at every depth and
//     allocates on every refusal (Rel builds a "../.." ladder or an error
//     message), so the expensive path is the one an attacker picks.
//   - Containment has no cheap refusal: diverging at the first component vs.
//     the last cost within a few percent of each other, because Rel's early
//     break still copies the whole remaining target into its result. HasDotDot
//     diverges by ~600x between the same two positions, which is why the
//     hygiene predicate is the cheap way to ask whether a name traverses.
//
// Every fixture is built at package scope, outside the measured closures — a
// strings.Repeat or `+` inside an AllocsPerRun closure measures the fixture,
// not the function under test.

// Depths for the size ladders. Each rung is 16x the previous, so a walk that
// became quadratic reports ~256x instead of ~16x between rungs — visible past
// the tracker's 150% threshold and past hosted-runner amplitude.
const (
	shallowDepth = 2
	mediumDepth  = 32
	deepDepth    = 512
)

// longComponentBytes is one path component long enough that a per-BYTE cost
// separates from a per-COMPONENT cost. A component-counting walk should barely
// notice it; a rune-decoding one will.
const longComponentBytes = 4096

// boolSink absorbs every predicate result so the compiler cannot discard the
// call being timed. b.Loop already guarantees the loop body executes, but a
// store to a package-level variable makes the guarantee independent of that.
var boolSink bool

// The containment corpus. Fixtures go through fs (filepath.FromSlash, defined
// in pathinside_test.go) so the literals read as paths here while the benchmark
// exercises the platform's real separator.
var (
	// benchRoot is the confinement boundary every containment case is judged
	// against, written cleanly on purpose: TestRootContainsRootSpellingCosts is
	// where an uncleanly-written root's per-call cost is measured.
	benchRoot = pathinside.Root(fs("/srv/data"))

	// benchDeepRoot is a root deep enough that the LAST-component refusal below
	// has to walk something before it can differ.
	benchDeepRoot = pathinside.Root(fs("/srv/data/" + strings.Repeat("c/", deepDepth) + "x"))

	// containedShallow, containedMedium and containedDeep are the accept path at
	// each ladder rung: a real descendant, cleanly written.
	containedShallow = containedPath(shallowDepth)
	containedMedium  = containedPath(mediumDepth)
	containedDeep    = containedPath(deepDepth)

	// escapeFirstComponent diverges from benchRoot at the very first component,
	// so Rel's comparison loop breaks immediately — and then copies the whole
	// remaining target into a "../.." ladder, which is why this is not the
	// cheap case a reader would predict.
	escapeFirstComponent = fs("/etc/" + strings.Repeat("c/", deepDepth) + "leaf.txt")

	// escapeLastComponent is a sibling of benchDeepRoot differing only in its
	// final component, so Rel's comparison loop walks every component before it
	// can decide. Paired with escapeFirstComponent at a deliberately similar
	// total length: the two together answer whether Rel has an early-out worth
	// anything, or whether the comparison loop and the result build simply trade
	// places.
	escapeLastComponent = fs("/srv/data/" + strings.Repeat("c/", deepDepth) + "y")

	// prefixSibling is the case the library exists for: a directory whose name
	// merely extends the root's, which strings.HasPrefix accepts and this
	// package must refuse.
	prefixSibling = fs("/srv/data-evil/leaf.txt")

	// uncomparableTarget is relative where benchRoot is absolute, so Rel cannot
	// compare the pair and reports an error. Kept deep on purpose: Rel builds
	// its refusal message by concatenating BOTH paths, so this measures a
	// refusal whose byte cost an attacker sizes.
	uncomparableTarget = relPath(deepDepth)
)

// The hygiene corpus, judged without a root.
var (
	// hygieneShallow, hygieneMedium and hygieneDeep hold no ".." at all, which
	// is HasDotDot's worst case: it must walk every component to answer false.
	hygieneShallow = relPath(shallowDepth)
	hygieneMedium  = relPath(mediumDepth)
	hygieneDeep    = relPath(deepDepth)

	// dotDotFirst, dotDotMiddle and dotDotLast put the traversal at each end and
	// in the middle of an otherwise identical path. HasDotDot returns on the first
	// match, so first is O(1) and last is O(depth); BenchmarkHasDotDotPosition
	// times that pair. dotDotMiddle carries no series of its own — it would only
	// interpolate between them — and stays as a contract-test fixture, because
	// the allocation claim has to hold for a traversal the scan reaches late.
	dotDotFirst  = fs("../" + strings.Repeat("c/", deepDepth) + "leaf.txt")
	dotDotMiddle = fs(strings.Repeat("c/", deepDepth/2) + "../" + strings.Repeat("c/", deepDepth/2) + "leaf.txt")
	dotDotLast   = fs(strings.Repeat("c/", deepDepth) + "..")

	// longComponent is one component of longComponentBytes bytes and no
	// separator at all — the byte-cost fixture.
	longComponent = strings.Repeat("x", longComponentBytes)

	// nonASCII is a path whose components are multi-byte. These predicates
	// compare bytes and split on a separator byte, so this should cost what its
	// LENGTH costs and nothing more; a regression that starts decoding runes
	// shows up here and nowhere else.
	nonASCII = fs("Ünïcødé/日本語/файл.txt/ελληνικά")

	// escapeFirstRel is canonical and escapes, so Clean rewrites nothing and the
	// separator-precise prefix test answers on the first two bytes — which buys
	// nothing, because Clean has already walked the whole path by then. That is
	// why it carries no series of its own: it would track
	// BenchmarkRelEscapes/canonical_depth_512 exactly (measured 1302 ns against
	// 1275 ns). It stays here to hold the zero-allocation claim for an input that
	// both escapes and is clean.
	escapeFirstRel = fs("../" + strings.Repeat("c/", deepDepth) + "leaf.txt")

	// buriedTraversal is the unclean input the two axes were built to disagree
	// on, and the one RelEscapes/IsCanonical input class that allocates: Clean
	// must build a new string because the result is not a prefix of the input.
	buriedTraversal = fs(strings.Repeat("c/", deepDepth) + "../../etc/shadow")

	// redundantSeparators is unclean by doubled separators rather than by
	// traversal, the other way Clean is forced to rewrite.
	redundantSeparators = fs("/srv/data//sub///" + strings.Repeat("c//", deepDepth) + "file.txt")
)

// degenerateTargets is the adversarial corpus a security-adjacent path judge
// actually sees, held as one set because what matters is that the whole class
// stays cheap rather than which member is cheapest. Every member is also gated
// individually for allocations by the tests below.
var degenerateTargets = []string{
	fs("/srv/data"),      // target equals root: contained, and Rel's early return
	fs("/srv/data/"),     // trailing separator on the root itself
	fs("/srv/data/sub/"), // trailing separator on a descendant
	fs("///"),            // nothing but separators
	fs("/"),              // the filesystem root
	"",                   // the empty string
	fs(".."),             // a bare traversal
	fs("../.."),          // a doubled traversal
	fs("/srv/data/.."),   // a traversal that cancels the root
	fs("..extras/x"),     // a NAME that merely begins with two dots
	fs("key..v2"),        // two dots inside a component
	fs("..."),            // three dots is a directory name
	longComponent,        // one very long component
	nonASCII,             // multi-byte components
}

// containedPath returns an absolute path depth components below benchRoot's
// tree, cleanly written.
func containedPath(depth int) string {
	return fs("/srv/data/" + strings.Repeat("c/", depth) + "leaf.txt")
}

// relPath returns a clean relative name depth components deep.
func relPath(depth int) string {
	return fs(strings.Repeat("c/", depth) + "leaf.txt")
}

// skipAllocContractOnWindows skips an allocation-contract test on Windows,
// where these functions genuinely do allocate: filepath.ToSlash rewrites every
// backslash and filepath.Clean rewrites separators, so both return a fresh
// string for input that needs no other change. The contract asserted below is
// therefore a Unix one — which is where it gates, since the fleet's CI matrix is
// ubuntu-24.04 only and every consumer of this library runs in a Linux
// container.
func skipAllocContractOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("allocation contract is Unix-only: on %s filepath.ToSlash and "+
			"filepath.Clean rewrite separators and so allocate", runtime.GOOS)
	}
}

// TestHasDotDotAllocations pins the strongest of the four contracts: HasDotDot
// is allocation-free, unconditionally.
//
// This is the function the README's "never cleans" claim rests on. It is the
// only one of the four that does not call filepath.Clean, and the measurement
// says it allocates nothing on any input class — traversal at either end or
// buried in the middle, a 4 KiB single component, multi-byte components, nothing
// but separators, the empty string. So the assertion is a flat `== 0` for every
// row rather than a per-class rule.
//
// What it catches: the two wrong spellings this package exists to centralize.
// strings.Split in place of strings.SplitSeq allocates a slice per call, and any
// rewrite that materializes the components (or reaches for a regexp) does the
// same. Both would pass every behavioural test in this repo.
//
// No t.Parallel here or in the siblings below: testing.AllocsPerRun pins
// GOMAXPROCS to 1 and measures process-wide allocation, so a parallel sibling's
// allocations land in this measurement.
func TestHasDotDotAllocations(t *testing.T) {
	skipAllocContractOnWindows(t)

	tests := map[string]string{
		"clean shallow path":         hygieneShallow,
		"clean deep path":            hygieneDeep,
		"traversal first component":  dotDotFirst,
		"traversal middle component": dotDotMiddle,
		"traversal last component":   dotDotLast,
		"bare traversal":             fs(".."),
		"buried traversal":           buriedTraversal,
		"redundant separators":       redundantSeparators,
		"trailing separator":         fs("/srv/data/sub/"),
		"only separators":            fs("///"),
		"empty string":               "",
		"long single component":      longComponent,
		"non-ascii components":       nonASCII,
		"names that merely dot":      fs("key..v2/.../..extras/a..b"),
	}

	for desc, p := range tests {
		t.Run(sub(desc), func(t *testing.T) {
			if got := testing.AllocsPerRun(200, func() {
				boolSink = pathinside.HasDotDot(p)
			}); got != 0 {
				t.Errorf("HasDotDot(%s) allocated %v times per run, want 0: the "+
					"hygiene axis judges a path as written and must not build one",
					short(p), got)
			}
		})
	}
}

// TestRelEscapesAllocations pins RelEscapes' contract on canonical input, which
// is the input class the package's own documentation says a caller should be
// handing it.
//
// RelEscapes is filepath.Clean plus two comparisons, and Clean returns a
// substring of its argument whenever it has nothing to rewrite. So a canonical
// name is judged for free, and that is the number worth gating: it says the
// second half of the containment rule costs nothing on well-formed input.
//
// The unclean classes are NOT asserted at zero, because they measured 2 and
// asserting zero there would be asserting a bug. Their property is a different
// one, and it is the one TestRefusalCostDoesNotGrowWithTheInput holds.
func TestRelEscapesAllocations(t *testing.T) {
	skipAllocContractOnWindows(t)

	// Every entry is already in filepath.Clean form, verified by the guard in
	// the loop rather than by assertion: a fixture that is quietly unclean would
	// make this test pass for the wrong reason if the contract were ever
	// loosened.
	tests := map[string]string{
		"clean shallow name":        hygieneShallow,
		"clean medium name":         hygieneMedium,
		"clean deep name":           hygieneDeep,
		"canonical escape at front": escapeFirstRel,
		"bare traversal":            fs(".."),
		"doubled traversal":         fs("../.."),
		"dot":                       ".",
		"absolute path":             fs("/etc/passwd"),
		"name that merely dots":     fs("..extras/movie.mkv"),
		"long single component":     longComponent,
		"non-ascii components":      nonASCII,
	}

	for desc, rel := range tests {
		t.Run(sub(desc), func(t *testing.T) {
			if !pathinside.IsCanonical(rel) {
				t.Fatalf("fixture %s is not canonical, so it cannot witness the "+
					"canonical-input contract", short(rel))
			}
			if got := testing.AllocsPerRun(200, func() {
				boolSink = pathinside.RelEscapes(rel)
			}); got != 0 {
				t.Errorf("RelEscapes(%s) allocated %v times per run, want 0: a "+
					"canonical name must be judged without building a second string",
					short(rel), got)
			}
		})
	}
}

// TestIsCanonicalAllocations pins the same contract for the other half of the
// hygiene axis: a path that IS canonical is judged for free.
//
// The asymmetry is worth stating, because it is the shape of the function. Every
// input that answers true is allocation-free by construction, since Clean
// returned the argument unchanged; an input that answers false may or may not
// allocate depending on whether Clean could truncate or had to rewrite. So the
// gateable claim is the true side, and that is what this asserts.
func TestIsCanonicalAllocations(t *testing.T) {
	skipAllocContractOnWindows(t)

	tests := map[string]string{
		"canonical shallow path": containedShallow,
		"canonical deep path":    containedDeep,
		"canonical relative":     hygieneDeep,
		"canonical traversal":    fs(".."),
		"canonical up and down":  fs("../dumps"),
		"dot":                    ".",
		"filesystem root":        fs("/"),
		"long single component":  longComponent,
		"non-ascii components":   nonASCII,
	}

	for desc, p := range tests {
		t.Run(sub(desc), func(t *testing.T) {
			if !pathinside.IsCanonical(p) {
				t.Fatalf("fixture %s is not canonical, so it cannot witness the "+
					"canonical-input contract", short(p))
			}
			if got := testing.AllocsPerRun(200, func() {
				boolSink = pathinside.IsCanonical(p)
			}); got != 0 {
				t.Errorf("IsCanonical(%s) allocated %v times per run, want 0: "+
					"confirming a path is already clean must not produce a cleaned "+
					"copy of it", short(p), got)
			}
		})
	}
}

// TestRootContainsAllocations pins the containment axis's accept path at zero.
//
// This is the assertion that makes "cheap lexical gate" a checkable statement
// rather than a slogan. filepath.Rel returns the constant "." when the target IS
// the root and a substring of the target when the target is beneath it, so the
// whole accept path allocates nothing — at depth 2 and at depth 512 alike, which
// is the second half of the claim: the cost of admitting a path does not depend
// on how deep it is.
//
// The empty root is included because it is a different mechanism: Root("")
// short-circuits before Rel, and a refactor that dropped the short-circuit would
// both change the answer and start allocating (Rel refuses the pair and builds a
// message). The allocation reading is the earlier of the two signals.
func TestRootContainsAllocations(t *testing.T) {
	skipAllocContractOnWindows(t)

	tests := map[string]struct {
		root   pathinside.Root
		target string
	}{
		"target equals root":       {benchRoot, fs("/srv/data")},
		"target is root plus sep":  {benchRoot, fs("/srv/data/")},
		"shallow descendant":       {benchRoot, containedShallow},
		"medium descendant":        {benchRoot, containedMedium},
		"deep descendant":          {benchRoot, containedDeep},
		"descendant trailing sep":  {benchRoot, fs("/srv/data/sub/")},
		"long single component":    {benchRoot, fs("/srv/data/" + longComponent)},
		"non-ascii descendant":     {benchRoot, fs("/srv/data/" + nonASCII)},
		"relative root and target": {pathinside.Root(fs("data")), fs("data/x/y")},
		"empty root refuses":       {pathinside.Root(""), containedDeep},
	}

	for desc, tt := range tests {
		t.Run(sub(desc), func(t *testing.T) {
			if got := testing.AllocsPerRun(200, func() {
				boolSink = tt.root.Contains(tt.target)
			}); got != 0 {
				t.Errorf("Root(%s).Contains(%s) allocated %v times per run, want 0: "+
					"admitting a contained path must not build a string",
					short(string(tt.root)), short(tt.target), got)
			}
		})
	}
}

// TestRootContainsRootSpellingCosts records the one place where this package's
// documented equivalence is an equivalence of ANSWERS and not of COST.
//
// Both the README and Root's own doc comment say that Root("/a/b/"),
// Root("/a/./b") and Root("/a/b") judge every target identically, and they do.
// But the root is re-cleaned inside filepath.Rel on every single call, so the
// spelling decides whether that cleaning is free: a trailing separator is
// truncated out of a substring and costs nothing, while a "." component forces
// Clean to build a new string, on every target, forever. A long-lived Root
// constructed from an unclean configuration value therefore pays an allocation
// per judged path for the life of the process.
//
// This asserts only the direction it can defend — the clean and trailing-separator
// spellings are free, the "." spelling is not free — rather than an exact count
// for the unclean case, which is a filepath.Clean implementation detail. It is
// here so that a future change which makes the equivalence cost-neutral (by
// cleaning the root once at construction, say) shows up as a deliberate decision
// rather than as an unexplained chart movement.
func TestRootContainsRootSpellingCosts(t *testing.T) {
	skipAllocContractOnWindows(t)

	target := containedDeep

	free := map[string]pathinside.Root{
		"clean root":                 pathinside.Root(fs("/srv/data")),
		"trailing separator":         pathinside.Root(fs("/srv/data/")),
		"doubled trailing separator": pathinside.Root(fs("/srv/data//")),
	}
	for desc, root := range free {
		t.Run(sub(desc), func(t *testing.T) {
			if got := testing.AllocsPerRun(200, func() {
				boolSink = root.Contains(target)
			}); got != 0 {
				t.Errorf("Root(%s).Contains(%s) allocated %v times per run, want 0",
					short(string(root)), short(target), got)
			}
		})
	}

	t.Run("dot_component_root_is_not_free", func(t *testing.T) {
		root := pathinside.Root(fs("/srv/./data"))
		if !root.Contains(target) {
			t.Fatalf("Root(%s).Contains(%s) = false, want true: the fixture must "+
				"answer the same as the clean spelling", short(string(root)), short(target))
		}
		if got := testing.AllocsPerRun(200, func() {
			boolSink = root.Contains(target)
		}); got == 0 {
			t.Errorf("Root(%s).Contains(%s) allocated %v times per run, want more "+
				"than 0: if a root written with a %q component is now free, the "+
				"root is being cleaned once instead of per call and this test "+
				"should be replaced by a zero assertion",
				short(string(root)), short(target), got, ".")
		}
	})
}

// TestRefusalCostDoesNotGrowWithTheInput holds the property that matters for a
// security gate, on the paths where allocation-freedom is not available.
//
// Every refusal allocates, because filepath.Rel builds either a "../.." ladder
// or an error message, and the caller that triggers a refusal is by definition
// the untrusted one. An attacker who can make a refusal a hundred times more
// expensive by sending a hundred times more path has found an amplification
// vector inside the containment check. So the assertion is not that refusal is
// free, it is that refusal's allocation count is BOUNDED and does not track the
// attacker's input length.
//
// The measured shape, which is why the bound is what it is: allocation counts
// step from 1 to 2 (escape) and 2 to 4 (uncomparable pair) as the constructed
// string crosses size classes, then stay flat from 16 components to 256. Byte
// volume does grow with the input — Rel's refusal message concatenates both
// paths — and that is a cost this test deliberately does not gate, because the
// count staying flat is the property that distinguishes bounded work from
// amplification.
func TestRefusalCostDoesNotGrowWithTheInput(t *testing.T) {
	skipAllocContractOnWindows(t)

	// A generous ceiling on purpose: the point is that the number does not
	// track depth, not that it is any particular small value.
	const maxRefusalAllocs = 8

	depths := []int{1, 4, 16, 64, 256}

	tests := map[string]func(depth int) (pathinside.Root, string){
		"escape at first component": func(depth int) (pathinside.Root, string) {
			return benchRoot, fs("/etc/" + strings.Repeat("c/", depth) + "leaf.txt")
		},
		"escape at last component": func(depth int) (pathinside.Root, string) {
			root := pathinside.Root(fs("/srv/data/" + strings.Repeat("c/", depth) + "x"))
			return root, fs("/srv/data/" + strings.Repeat("c/", depth) + "y")
		},
		"uncomparable pair": func(depth int) (pathinside.Root, string) {
			return benchRoot, relPath(depth)
		},
		"prefix sibling": func(depth int) (pathinside.Root, string) {
			return benchRoot, fs("/srv/data-evil/" + strings.Repeat("c/", depth) + "leaf.txt")
		},
	}

	for desc, build := range tests {
		t.Run(sub(desc), func(t *testing.T) {
			for _, depth := range depths {
				root, target := build(depth)
				if root.Contains(target) {
					t.Errorf("Root(%s).Contains(%s) = true, want false: the fixture "+
						"must exercise the refusal path", short(string(root)), short(target))
					continue
				}
				got := testing.AllocsPerRun(200, func() {
					boolSink = root.Contains(target)
				})
				if got > maxRefusalAllocs {
					t.Errorf("Root(%s).Contains(%s) allocated %v times per run at "+
						"depth %d, want at most %d: refusal cost must not grow with "+
						"the path an attacker supplies",
						short(string(root)), short(target), got, depth, maxRefusalAllocs)
				}
			}
		})
	}
}

// TestHygieneRefusalCostDoesNotGrowWithTheInput is the same property for the
// hygiene axis's one allocating class.
//
// RelEscapes and IsCanonical allocate when filepath.Clean has to rewrite, and
// unclean input is exactly what an attacker supplies (the package's own
// documentation makes that point: the two axes diverge only on unclean input).
// The measurement says the count is a flat 2 from one buried traversal to 512 of
// them, so the collapse work Clean does is not paid for in allocations. That
// flatness is the property; assert it directly rather than the constant, so the
// test survives a Clean that grows a second buffer without becoming
// input-proportional.
func TestHygieneRefusalCostDoesNotGrowWithTheInput(t *testing.T) {
	skipAllocContractOnWindows(t)

	const maxUncleanAllocs = 8

	for _, depth := range []int{1, 4, 16, 64, 256} {
		p := fs(strings.Repeat("c/../", depth) + "leaf.txt")
		if pathinside.IsCanonical(p) {
			t.Errorf("IsCanonical(%s) = true, want false: the fixture must be "+
				"unclean to exercise the rewriting path", short(p))
			continue
		}

		relAllocs := testing.AllocsPerRun(200, func() {
			boolSink = pathinside.RelEscapes(p)
		})
		if relAllocs > maxUncleanAllocs {
			t.Errorf("RelEscapes(%s) allocated %v times per run at depth %d, want "+
				"at most %d", short(p), relAllocs, depth, maxUncleanAllocs)
		}

		canonAllocs := testing.AllocsPerRun(200, func() {
			boolSink = pathinside.IsCanonical(p)
		})
		if canonAllocs > maxUncleanAllocs {
			t.Errorf("IsCanonical(%s) allocated %v times per run at depth %d, want "+
				"at most %d", short(p), canonAllocs, depth, maxUncleanAllocs)
		}

		// HasDotDot sees the same hostile input and never cleans it, so it is
		// held to the strict contract even here. This is the axis separation
		// stated as a cost: the hygiene predicate that never cleans never pays.
		if got := testing.AllocsPerRun(200, func() {
			boolSink = pathinside.HasDotDot(p)
		}); got != 0 {
			t.Errorf("HasDotDot(%s) allocated %v times per run at depth %d, want 0",
				short(p), got, depth)
		}
	}
}

// BenchmarkRootContains measures the containment accept path across depths — the
// hot path in production, where a path that IS inside is judged once per file.
//
// Size-parameterised because the cost model is the claim: filepath.Rel compares
// components pairwise in one forward pass, so 16x the components should cost
// roughly 16x, not 256x. A rewrite that split both paths into slices, or
// compared every component against every other, shows up as a super-linear jump
// between rungs while each individual number still looks small.
func BenchmarkRootContains(b *testing.B) {
	cases := []struct {
		name   string
		target string
	}{
		{"contained_depth_" + strconv.Itoa(shallowDepth), containedShallow},
		{"contained_depth_" + strconv.Itoa(mediumDepth), containedMedium},
		{"contained_depth_" + strconv.Itoa(deepDepth), containedDeep},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				boolSink = benchRoot.Contains(tc.target)
			}
		})
	}
}

// BenchmarkRootContainsRefusal measures the four ways containment says no. It is
// the number that matters under attack, since every one of these is a shape a
// caller does not choose.
//
// The first two rows are a deliberate pair at a deliberately similar total
// length, and they exist to answer one question: does diverging at the FIRST
// component cost less than diverging at the LAST? filepath.Rel breaks its
// comparison loop at the first differing component, which suggests it should. It
// does not. The two measured within a few percent of each other, because Rel then
// copies the whole remaining target into a "../.." ladder — the early-out moves
// the work rather than avoiding it, and there is no cheap refusal to route hostile
// input through. Keep both series: a future Go whose Rel gains a real early-out
// would show up as these two diverging, which is a fact worth learning from a
// chart rather than from a re-measurement.
//
// uncomparable_pair is the row to watch. Rel refuses an absolute-against-relative
// pair by building an error message that concatenates BOTH paths — a string this
// package then discards, because Contains only reads the error's existence. It is
// the most expensive refusal available and its byte cost is sized by the caller.
func BenchmarkRootContainsRefusal(b *testing.B) {
	cases := []struct {
		name   string
		root   pathinside.Root
		target string
	}{
		{"escape_at_first_component", benchRoot, escapeFirstComponent},
		{"escape_at_last_component", benchDeepRoot, escapeLastComponent},
		{"prefix_sibling", benchRoot, prefixSibling},
		{"uncomparable_pair", benchRoot, uncomparableTarget},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if tc.root.Contains(tc.target) {
				b.Fatalf("Root(%s).Contains(%s) = true, want false: this benchmark "+
					"must measure the refusal path", short(string(tc.root)), short(tc.target))
			}
			b.ReportAllocs()
			for b.Loop() {
				boolSink = tc.root.Contains(tc.target)
			}
		})
	}
}

// BenchmarkHasDotDot measures the hygiene axis's worst case across depths: a
// path with no traversal anywhere, so every component must be examined before
// the answer can be false.
//
// This is the ladder that guards the separator rule's implementation. The
// current shape is one pass over the bytes with a range-over-func split, and it
// allocates nothing; a rewrite to strings.Split would allocate a slice
// proportional to the component count, and one that built each component as a
// string would allocate per component. Either shows up here as a step change in
// B/op and allocs/op that is far larger at 512 components than at 32 — which is
// why this is size-parameterised rather than measured at one depth.
//
// The ladder starts at 32 rather than at a shallow path deliberately: a
// two-component path measures 12.8 ns, which is fixed call overhead rather than
// walking, so it muddies the complexity ratio the rungs exist to report. The
// constant-cost end of this function is covered by
// BenchmarkHasDotDotPosition/dotdot_at_first_component, and shallow paths fill
// most of BenchmarkDegenerateInputs below.
func BenchmarkHasDotDot(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"clean_depth_" + strconv.Itoa(mediumDepth), hygieneMedium},
		{"clean_depth_" + strconv.Itoa(deepDepth), hygieneDeep},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if pathinside.HasDotDot(tc.path) {
				b.Fatalf("HasDotDot(%s) = true, want false: this benchmark must "+
					"measure the full walk", short(tc.path))
			}
			b.ReportAllocs()
			for b.Loop() {
				boolSink = pathinside.HasDotDot(tc.path)
			}
		})
	}
}

// BenchmarkHasDotDotPosition measures the early-out by moving the traversal from
// the front of a path to its end, holding everything else identical.
//
// HasDotDot returns on the first ".." component, so first is O(1) and last is
// O(depth) — a factor of roughly 600 apart at depth 512 across local runs, which
// is the durable figure; the absolute nanoseconds move with the machine.
// Two series rather than one, because the RELATIONSHIP between them is the
// regression signal: if they ever converge, the loop stopped returning early and
// now examines every component of every path it is handed. That is a real cost at
// a call site which runs once per file, and it is invisible to every behavioural
// test in this repo, because the answer never changes.
func BenchmarkHasDotDotPosition(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"dotdot_at_first_component", dotDotFirst},
		{"dotdot_at_last_component", dotDotLast},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if !pathinside.HasDotDot(tc.path) {
				b.Fatalf("HasDotDot(%s) = false, want true: this benchmark must "+
					"measure a path that does hold a traversal", short(tc.path))
			}
			b.ReportAllocs()
			for b.Loop() {
				boolSink = pathinside.HasDotDot(tc.path)
			}
		})
	}
}

// BenchmarkHasDotDotShape separates the cost variable the depth ladder cannot:
// bytes, as distinct from components.
//
// The path here is multi-byte throughout. It should cost what its LENGTH costs
// and nothing more, because the implementation splits on a separator byte and
// compares against the two-byte literal "..". A rewrite that decoded runes — a
// `for _, r := range` over the path, or a Unicode-aware normalization added to
// chase Windows case folding — would move this series sharply and leave the ASCII
// ladder flat, and no behavioural test in this repo would notice.
//
// It is a series of its own rather than a row in the degenerate corpus below
// precisely because the corpus would hide it: a 4x regression on one of fourteen
// aggregated inputs is a 1.2x move on the corpus total, under the tracker's 150%
// threshold. The corpus is the right home for an input whose regression would be
// enormous (a quadratic byte scan on the 4 KiB single component in it), and the
// wrong home for one whose regression is merely large.
//
// Kept as a single-row table on purpose: the b.Run wrapper means a second shape
// can be added later without renaming this series, and a chart series name is
// permanent.
func BenchmarkHasDotDotShape(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"non_ascii_components", nonASCII},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				boolSink = pathinside.HasDotDot(tc.path)
			}
		})
	}
}

// BenchmarkRelEscapes measures the containment rule's rootless half.
//
// canonical_depth_512 is the whole cost model: filepath.Clean walks the entire
// path before the separator-precise prefix test gets to look at the first two
// bytes, so RelEscapes has NO early-out. Measured, a name that escapes at its
// very front costs 1302 ns against 1251 ns for one that does not escape at all —
// the same number. That is the opposite of HasDotDot's behaviour on the same
// input (4.8 ns), and it is the reason the cheap way to ask "does this name
// traverse" is the hygiene predicate rather than this one. The escaping row is
// therefore not carried as a separate series: it would track this one exactly.
//
// unclean_buried_traversal is the allocating row, and the only one of the two
// that produces a string. It is also the input class the two axes were built to
// disagree on, so it is where an allocation regression would be easiest to
// mistake for correct behaviour.
func BenchmarkRelEscapes(b *testing.B) {
	cases := []struct {
		name string
		rel  string
	}{
		{"canonical_depth_" + strconv.Itoa(deepDepth), hygieneDeep},
		{"unclean_buried_traversal", buriedTraversal},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				boolSink = pathinside.RelEscapes(tc.rel)
			}
		})
	}
}

// BenchmarkIsCanonical measures the hygiene axis's other half, which is one
// filepath.Clean and one string comparison.
//
// The canonical case is the one worth a permanent series: the path is walked and
// handed back as a substring, so the comparison is a pointer-and-length equality
// and nothing allocates. That is the property a naive rewrite stops
// special-casing, and an allocation regression here would be silent behaviourally.
// The unclean case is not carried separately because it is the same
// filepath.Clean rewrite that BenchmarkRelEscapes/unclean_buried_traversal
// already tracks; what is specific to this function is the free side.
//
// Kept as a single-row table so a row can be added later without renaming this
// series.
func BenchmarkIsCanonical(b *testing.B) {
	cases := []struct {
		name string
		path string
	}{
		{"canonical_depth_" + strconv.Itoa(deepDepth), containedDeep},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				boolSink = pathinside.IsCanonical(tc.path)
			}
		})
	}
}

// BenchmarkDegenerateInputs measures the adversarial corpus a security-adjacent
// path judge actually sees: `..` at every position, nothing but separators, a
// trailing separator, the filesystem root, the empty string, names that merely
// begin with two dots, a 4 KiB component, multi-byte components, and a target
// equal to its root.
//
// One series per axis rather than one per input, deliberately. What matters for
// this corpus is that the whole hostile class stays cheap, not which member is
// cheapest, and each member is already gated individually for allocations by the
// tests above — where per-input precision costs nothing, unlike here, where each
// name would become a permanent chart series and a second of every weekly run.
// One iteration judges the entire corpus, so ns/op is the corpus total: read it
// as a per-class number, and divide by the corpus length before comparing it to
// any single-input series.
func BenchmarkDegenerateInputs(b *testing.B) {
	b.Run("containment_corpus", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, target := range degenerateTargets {
				boolSink = benchRoot.Contains(target)
			}
		}
	})

	b.Run("hygiene_corpus", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			// Each result folds into acc (!= is XOR on bools) rather than
			// overwriting one shared sink three times: consecutive stores to a
			// single variable leave the earlier ones dead, and a dead store is
			// exactly the shape a compiler may remove along with the pure call
			// that fed it.
			acc := false
			for _, p := range degenerateTargets {
				acc = acc != pathinside.HasDotDot(p)
				acc = acc != pathinside.IsCanonical(p)
				acc = acc != pathinside.RelEscapes(p)
			}
			boolSink = acc
		}
	})
}

// sub turns a human-readable case description into a subtest name the runner and
// -run can address: an identifier-ish token with no spaces and, critically, no
// "/", which -run reads as its path separator. Path fixtures are full of
// slashes, so they stay in the case DATA and never in its name.
func sub(desc string) string {
	return strings.ReplaceAll(desc, " ", "_")
}

// short renders a path for a failure message: quoted in full when it is short
// enough to read, and as a quoted head plus a byte count when it is not. The
// fixtures here run to five kilobytes, and the convention is to identify the
// input OR describe it when the input is large — a whole 512-component path in a
// t.Errorf buries the rest of the line and the next failure with it. The subtest
// name carries the case identity either way.
//
// The head is trimmed to a rune boundary, because these fixtures are
// deliberately non-ASCII in places and a cut through a multi-byte rune renders
// as an escaped fragment that reads like corrupted input rather than like a
// truncated one.
func short(p string) string {
	const maxQuoted = 48
	if len(p) <= maxQuoted {
		return strconv.Quote(p)
	}
	head := strings.ToValidUTF8(p[:maxQuoted], "")
	return strconv.Quote(head) + "\u2026 (" + strconv.Itoa(len(p)) + " bytes)"
}
