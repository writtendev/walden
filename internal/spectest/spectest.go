// Package spectest reads the JSON examples out of a published specification document.
//
// Both published formats — spec/journal/v1 and spec/auth/v1 — say their examples are real
// records taken from their fixtures, and each has a conformance gate that holds them to it.
// The gates differ in what they compare an example against; how an example is found in a
// markdown document is the same question twice, so it is answered once, here. A second copy
// of this reader would be a second set of blind spots, and the weaker of the two would guard
// a published interface without anyone noticing which one it was.
package spectest

import (
	"encoding/json"
	"errors"
	"strings"
)

// Example is one ```json fenced block of a specification document.
type Example struct {
	// Start and End bound the block body: Start is the index of its first line, End the
	// index of the closing fence. Start is therefore also the 1-based line number of the
	// opening fence, which is what a failure message wants to name.
	Start int
	End   int
	// Body is the block's content with any blockquote markers taken off, newline-terminated.
	Body string
}

// ErrUnterminatedFence reports a fenced block that the document never closes.
var ErrUnterminatedFence = errors.New("unterminated fenced block")

// JSONExamples returns every ```json fenced block of a specification document, in document
// order, along with the line indexes of JSON objects no such fence carries.
//
// The document is read twice. The first pass walks its fenced blocks and collects the ```json
// ones; the second sweeps every line the first did not claim and finds JSON by parsing it, so
// an example written as an indented code block, inside a blockquote, or under any other fence
// tag is reported as a stray rather than passing unseen.
//
// What neither pass sees is an example that is neither: not carried by a ```json fence, and
// not parseable as a JSON object from some line of its own through an unbroken run of lines,
// once one level of blockquote marker is off. Being incomplete is one way to land there — a
// fragment, a record with an ellipsis through it, one split by a blank line, one quoted twice
// over — but completeness is not the boundary. A whole record escapes just as readily whenever
// the line its object opens on does not itself begin with "{" after one blockquote strip:
// inline in a prose sentence, on one line in a table cell, or prefixed line by line inside a
// ```diff fence.
func JSONExamples(lines []string) (examples []Example, stray []int, err error) {
	// carried marks every line a ```json fence accounts for. What is left over is swept below.
	carried := make([]bool, len(lines))
	for i := 0; i < len(lines); i++ {
		marker, info, ok := fenceOpener(lines[i])
		if !ok {
			continue
		}
		_, quoted := stripQuote(lines[i])
		start := i + 1
		end := start
		for end < len(lines) && !fenceCloses(lines[end], marker) {
			end++
		}
		if end == len(lines) {
			return nil, nil, ErrUnterminatedFence
		}
		body := make([]string, 0, end-start)
		for _, line := range lines[start:end] {
			if quoted {
				line, _ = stripQuote(line)
			}
			body = append(body, line)
		}
		block := strings.Join(body, "\n") + "\n"
		i = end

		// A block that is not tagged json is prose, a key layout, or a refusal string, and
		// none of a conformance gate's business. If it holds a JSON document anyway it is an
		// example wearing the wrong fence, and the sweep below is what says so.
		if info != "json" {
			continue
		}
		for j := start - 1; j <= end; j++ {
			carried[j] = true
		}
		examples = append(examples, Example{Start: start, End: end, Body: block})
	}

	for i := 0; i < len(lines); i++ {
		if carried[i] {
			continue
		}
		end, ok := jsonObjectEnd(lines, i)
		if !ok {
			continue
		}
		stray = append(stray, i)
		i = end
	}
	return examples, stray, nil
}

// IsFence reports whether a line is a code fence. A gate reading the prose around an example
// — the sentence that cites the fixture it quotes, say — wants to stop where the prose stops,
// and this is that boundary, read the same way the block walk reads it.
func IsFence(line string) bool {
	_, _, ok := fenceOpener(line)
	return ok
}

// stripQuote removes a markdown blockquote marker from a line, and reports whether there
// was one. CommonMark lets a fenced block sit inside a blockquote, and the block's content
// is then its lines with that marker taken off — so this is how such a block is read back
// out. It matters twice over: ">" is not JSON whitespace, so a quoted record example does
// not parse until the marker is gone.
func stripQuote(line string) (rest string, quoted bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, ">") {
		return line, false
	}
	return strings.TrimPrefix(strings.TrimPrefix(trimmed, ">"), " "), true
}

// fenceOpener reports whether a line opens a fenced code block, and returns the fence marker
// and the info string. Both markdown fence characters count, at any indentation, inside a
// blockquote or out, because the question this asks is which examples a document carries —
// and an example does not stop being one for being written ~~~json, or for sitting inside a
// list item, or for being quoted.
//
// The marker is the whole run of fence characters, not the first three. CommonMark allows a
// longer run, and a longer run demands an at-least-as-long closer, so the length belongs to
// the marker rather than being a detail to round off. Read as three characters, ````json
// carries the info string "`json" — a legal json example nothing would then check — and its
// legal closer stops being recognizable as one.
func fenceOpener(line string) (marker, info string, ok bool) {
	trimmed, _ := stripQuote(line)
	trimmed = strings.TrimLeft(trimmed, " \t")
	for _, c := range []byte{'`', '~'} {
		run := 0
		for run < len(trimmed) && trimmed[run] == c {
			run++
		}
		if run >= 3 {
			return trimmed[:run], strings.TrimSpace(trimmed[run:]), true
		}
	}
	return "", "", false
}

// fenceCloses reports whether a line closes a block opened with marker. CommonMark's closer
// is a run of at least as many of the same fence character as the opener, with nothing after
// it but whitespace — so a longer run closes a shorter fence, and an info string disqualifies
// a line from closing anything.
func fenceCloses(line, marker string) bool {
	trimmed, _ := stripQuote(line)
	trimmed = strings.TrimSpace(trimmed)
	if !strings.HasPrefix(trimmed, marker) {
		return false
	}
	return strings.Trim(trimmed, marker[:1]) == ""
}

// looksLikeJSONDocument reports whether a run of text is a JSON object. A specification's
// untagged blocks are refusal strings, key layouts and HTTP headers, none of which parse;
// text that does parse is a record example, whatever markdown is wrapped around it.
func looksLikeJSONDocument(block string) bool {
	trimmed := strings.TrimSpace(block)
	return strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed))
}

// jsonObjectEnd reports whether a JSON object begins on line i and, if so, the line it ends
// on. The object is the shortest run of lines from i that parses, and the run stops at a blank
// line, which no record example contains.
//
// Nothing about the markdown around it is consulted, and that is the point: this finds JSON by
// being JSON. Indentation is left alone because JSON ignores whitespace; the blockquote marker
// is taken off because JSON does not ignore ">".
func jsonObjectEnd(lines []string, i int) (int, bool) {
	if first, _ := stripQuote(lines[i]); !strings.HasPrefix(strings.TrimSpace(first), "{") {
		return 0, false
	}
	var b strings.Builder
	for end := i; end < len(lines); end++ {
		line, _ := stripQuote(lines[end])
		if strings.TrimSpace(line) == "" {
			return 0, false
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if looksLikeJSONDocument(b.String()) {
			return end, true
		}
	}
	return 0, false
}
