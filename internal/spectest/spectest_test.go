package spectest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/spectest"
)

// TestJSONExamples pins the shapes of markdown this reader is meant to see through. Each
// document below is one line of the package comment made concrete: an example does not stop
// being an example for the fence it wears, and a JSON document that no ```json fence carries
// is a stray however it is dressed.
func TestJSONExamples(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		examples []string
		strays   int
	}{
		{
			name:     "plain fence",
			doc:      "text\n\n```json\n{\n  \"a\": 1\n}\n```\n\nmore\n",
			examples: []string{"{\n  \"a\": 1\n}\n"},
		},
		{
			name:     "quoted fence",
			doc:      "> ```json\n> {\n>   \"a\": 1\n> }\n> ```\n",
			examples: []string{"{\n  \"a\": 1\n}\n"},
		},
		{
			name:     "indented tilde fence",
			doc:      "  ~~~json\n  {\n    \"a\": 1\n  }\n  ~~~\n",
			examples: []string{"  {\n    \"a\": 1\n  }\n"},
		},
		{
			name:     "longer run is one marker",
			doc:      "````json\n{\n  \"a\": 1\n}\n````\n",
			examples: []string{"{\n  \"a\": 1\n}\n"},
		},
		{
			name:   "untagged fence holding json is a stray",
			doc:    "```\n{\n  \"a\": 1\n}\n```\n",
			strays: 1,
		},
		{
			name:   "indented code block is a stray",
			doc:    "text\n\n    {\n      \"a\": 1\n    }\n\nmore\n",
			strays: 1,
		},
		{
			name:   "blockquoted json is a stray",
			doc:    "> {\n>   \"a\": 1\n> }\n",
			strays: 1,
		},
		{
			name: "prose that merely mentions braces is not json",
			doc:  "A pattern like {repo} appears in every route.\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			examples, strays, err := spectest.JSONExamples(strings.Split(tc.doc, "\n"))
			if err != nil {
				t.Fatalf("JSONExamples failed: %v", err)
			}
			if len(examples) != len(tc.examples) {
				t.Fatalf("found %d json examples, want %d", len(examples), len(tc.examples))
			}
			for i, want := range tc.examples {
				if examples[i].Body != want {
					t.Errorf("example %d body:\ngot:\n%q\nwant:\n%q", i, examples[i].Body, want)
				}
			}
			if len(strays) != tc.strays {
				t.Errorf("found %d stray json documents, want %d", len(strays), tc.strays)
			}
		})
	}
}

// TestJSONExamplesUnterminatedFence covers the one failure the reader reports rather than
// working around: a document whose fence is never closed is malformed, and a gate reading it
// would otherwise silently drop everything after the opener.
//
// The line the fence opens on is part of the error, not decoration. A caller only knows the
// document's path, so the line is the whole difference between naming the defect and sending
// a maintainer through an 800-line file looking for it.
func TestJSONExamplesUnterminatedFence(t *testing.T) {
	doc := "intro\n\nsome prose\n\n```json\n{\n  \"a\": 1\n}\n"
	_, _, err := spectest.JSONExamples(strings.Split(doc, "\n"))
	if !errors.Is(err, spectest.ErrUnterminatedFence) {
		t.Fatalf("expected ErrUnterminatedFence, got %v", err)
	}
	if !strings.Contains(err.Error(), "line 5") {
		t.Errorf("error %q does not name line 5, where the fence opens", err)
	}
}
