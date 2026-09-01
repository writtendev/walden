package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// envLookup builds a lookupEnv function over a fixed map.
func envLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// creds is the environment every location test runs under, so that
// ResolveJournal has something to find.
var creds = map[string]string{
	store.EnvAccessKeyID:     "AKIAEXAMPLE",
	store.EnvSecretAccessKey: "wJalrXUtnFEMI",
}

func TestParseJournalURLLocations(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		env       map[string]string
		provider  string
		endpoint  string
		region    string
		bucket    string
		prefix    string
		pathStyle bool
	}{
		// AWS S3, s3:// shorthand.
		{
			name:     "aws-shorthand",
			raw:      "s3://my-bucket/walden",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-1.amazonaws.com",
			region:   "us-east-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-shorthand-bucket-root",
			raw:      "s3://my-bucket",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-1.amazonaws.com",
			region:   "us-east-1",
			bucket:   "my-bucket",
			prefix:   "",
		},
		{
			name:     "aws-shorthand-trailing-slash",
			raw:      "s3://my-bucket/walden/",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-1.amazonaws.com",
			region:   "us-east-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-shorthand-nested-prefix",
			raw:      "s3://my-bucket/backups/walden/",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-1.amazonaws.com",
			region:   "us-east-1",
			bucket:   "my-bucket",
			prefix:   "backups/walden",
		},
		{
			name:     "aws-shorthand-region-query",
			raw:      "s3://my-bucket/walden?region=eu-west-1",
			provider: "AWS S3",
			endpoint: "https://s3.eu-west-1.amazonaws.com",
			region:   "eu-west-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-shorthand-region-env",
			raw:      "s3://my-bucket/walden",
			env:      map[string]string{store.EnvRegion: "ap-south-1"},
			provider: "AWS S3",
			endpoint: "https://s3.ap-south-1.amazonaws.com",
			region:   "ap-south-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-shorthand-region-default-env",
			raw:      "s3://my-bucket/walden",
			env:      map[string]string{store.EnvDefaultRegion: "sa-east-1"},
			provider: "AWS S3",
			endpoint: "https://s3.sa-east-1.amazonaws.com",
			region:   "sa-east-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-shorthand-region-query-beats-env",
			raw:      "s3://my-bucket/walden?region=eu-west-1",
			env:      map[string]string{store.EnvRegion: "ap-south-1"},
			provider: "AWS S3",
			endpoint: "https://s3.eu-west-1.amazonaws.com",
			region:   "eu-west-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:      "aws-shorthand-style-path",
			raw:       "s3://my-bucket/walden?style=path",
			provider:  "AWS S3",
			endpoint:  "https://s3.us-east-1.amazonaws.com",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},

		// AWS S3, explicit endpoints.
		{
			name:      "aws-path-style",
			raw:       "https://s3.eu-west-1.amazonaws.com/my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "aws-virtual-hosted",
			raw:      "https://my-bucket.s3.eu-west-1.amazonaws.com/walden",
			provider: "AWS S3",
			endpoint: "https://s3.eu-west-1.amazonaws.com",
			region:   "eu-west-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:     "aws-virtual-hosted-bucket-named-like-endpoint",
			raw:      "https://s3-backups.s3.us-east-2.amazonaws.com/walden",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-2.amazonaws.com",
			region:   "us-east-2",
			bucket:   "s3-backups",
			prefix:   "walden",
		},
		{
			// A dotted bucket name is legal but cannot match an HTTPS
			// wildcard certificate one label deep, so it resolves
			// path-style however the URL was written.
			name:      "aws-dotted-bucket-forces-path-style",
			raw:       "https://my.dotted.bucket.s3.amazonaws.com/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.amazonaws.com",
			region:    "us-east-1",
			bucket:    "my.dotted.bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "aws-shorthand-dotted-bucket-forces-path-style",
			raw:       "s3://my.dotted.bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.us-east-1.amazonaws.com",
			region:    "us-east-1",
			bucket:    "my.dotted.bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// No certificate to match over plain HTTP, so an explicit
			// style=virtual on a dotted bucket stands.
			name:     "http-dotted-bucket-keeps-explicit-virtual-hosted",
			raw:      "http://minio.internal:9000/my.dotted.bucket/walden?style=virtual",
			endpoint: "http://minio.internal:9000",
			region:   "us-east-1",
			bucket:   "my.dotted.bucket",
			prefix:   "walden",
		},
		{
			// walden resolves a dotted bucket path-style whatever the URL
			// says, so an operator must be allowed to say it: refusing
			// style=path here refused the operator who asked for exactly
			// what walden had already chosen.
			name:      "dotted-bucket-accepts-explicit-style-path",
			raw:       "https://my.dotted.bucket.s3.eu-west-1.amazonaws.com/walden?style=path",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my.dotted.bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// The bucket is named by the hostname label under either
			// style; style only decides where the request writes it.
			name:      "hostname-bucket-accepts-explicit-style-path",
			raw:       "https://my-bucket.s3.eu-west-1.amazonaws.com/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: false,
		},
		{
			name:      "hostname-bucket-with-style-path",
			raw:       "https://my-bucket.s3.eu-west-1.amazonaws.com/walden?style=path",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// The query is case-insensitive throughout: the region has to
			// be folded for the SigV4 scope, so folding the keys and the
			// style value too is the rule an operator can remember.
			name:      "query-keys-are-case-insensitive",
			raw:       "s3://my-bucket/walden?REGION=EU-WEST-1&Style=PATH",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "aws-legacy-dash-region",
			raw:       "https://s3-eu-west-1.amazonaws.com/my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3-eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// FIPS is mandatory for GovCloud and FedRAMP, and the
			// modifier sits where the legacy s3-<region> form puts the
			// region. Read as one, this signed with region "fips".
			name:      "aws-fips",
			raw:       "https://s3-fips.us-east-1.amazonaws.com/my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3-fips.us-east-1.amazonaws.com",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "aws-fips-dualstack",
			raw:       "https://s3-fips.dualstack.us-east-1.amazonaws.com/my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3-fips.dualstack.us-east-1.amazonaws.com",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "aws-fips-virtual-hosted",
			raw:      "https://my-bucket.s3-fips.us-east-2.amazonaws.com/walden",
			provider: "AWS S3",
			endpoint: "https://s3-fips.us-east-2.amazonaws.com",
			region:   "us-east-2",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			// Accelerate names no region, so the operator must. With
			// ?region= there is nothing left to guess.
			name:      "aws-accelerate-with-explicit-region",
			raw:       "https://s3-accelerate.amazonaws.com/my-bucket/walden?region=eu-west-1",
			provider:  "AWS S3",
			endpoint:  "https://s3-accelerate.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "aws-dualstack",
			raw:       "https://s3.dualstack.us-west-2.amazonaws.com/my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.dualstack.us-west-2.amazonaws.com",
			region:    "us-west-2",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "aws-host-region-beats-env",
			raw:       "https://s3.eu-west-1.amazonaws.com/my-bucket/walden",
			env:       map[string]string{store.EnvRegion: "ap-south-1"},
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},

		// Cloudflare R2. The label in front of the suffix is the account.
		{
			name:      "r2-path-style",
			raw:       "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden",
			provider:  "Cloudflare R2",
			endpoint:  "https://a1b2c3.r2.cloudflarestorage.com",
			region:    "auto",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "r2-virtual-hosted",
			raw:      "https://my-bucket.a1b2c3.r2.cloudflarestorage.com/walden",
			provider: "Cloudflare R2",
			endpoint: "https://a1b2c3.r2.cloudflarestorage.com",
			region:   "auto",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:      "r2-fixed-region-beats-env",
			raw:       "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden",
			env:       map[string]string{store.EnvRegion: "us-east-1"},
			provider:  "Cloudflare R2",
			endpoint:  "https://a1b2c3.r2.cloudflarestorage.com",
			region:    "auto",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "r2-region-query-beats-fixed-region",
			raw:       "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden?region=wnam",
			provider:  "Cloudflare R2",
			endpoint:  "https://a1b2c3.r2.cloudflarestorage.com",
			region:    "wnam",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},

		// Google Cloud Storage.
		{
			name:      "gcs-path-style",
			raw:       "https://storage.googleapis.com/my-bucket/walden",
			provider:  "Google Cloud Storage",
			endpoint:  "https://storage.googleapis.com",
			region:    "auto",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "gcs-virtual-hosted",
			raw:      "https://my-bucket.storage.googleapis.com/walden/",
			provider: "Google Cloud Storage",
			endpoint: "https://storage.googleapis.com",
			region:   "auto",
			bucket:   "my-bucket",
			prefix:   "walden",
		},

		// Backblaze B2.
		{
			name:      "b2-path-style",
			raw:       "https://s3.us-west-004.backblazeb2.com/my-bucket/walden",
			provider:  "Backblaze B2",
			endpoint:  "https://s3.us-west-004.backblazeb2.com",
			region:    "us-west-004",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "b2-virtual-hosted",
			raw:      "https://my-bucket.s3.us-west-004.backblazeb2.com/walden",
			provider: "Backblaze B2",
			endpoint: "https://s3.us-west-004.backblazeb2.com",
			region:   "us-west-004",
			bucket:   "my-bucket",
			prefix:   "walden",
		},

		// Azure Blob Storage: the label in front of the suffix is the
		// account, and the container is the first path segment.
		{
			name:      "azure-path-style",
			raw:       "https://myaccount.blob.core.windows.net/my-container/walden",
			provider:  "Azure Blob Storage",
			endpoint:  "https://myaccount.blob.core.windows.net",
			region:    "auto",
			bucket:    "my-container",
			prefix:    "walden",
			pathStyle: true,
		},

		// MinIO, Ceph RGW, Garage: self-hosted under operator-chosen
		// hostnames, so an unrecognised host is read path-style.
		{
			name:      "minio-http-port",
			raw:       "http://minio.internal:9000/my-bucket/walden",
			endpoint:  "http://minio.internal:9000",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:      "ceph-rgw-https",
			raw:       "https://rgw.example.org/my-bucket/backups/walden/",
			endpoint:  "https://rgw.example.org",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "backups/walden",
			pathStyle: true,
		},
		{
			name:      "garage-region-env",
			raw:       "http://garage.example.net:3900/my-bucket/walden",
			env:       map[string]string{store.EnvRegion: "garage"},
			endpoint:  "http://garage.example.net:3900",
			region:    "garage",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			name:     "self-hosted-forced-virtual-hosted",
			raw:      "https://s3.example.org/my-bucket/walden?style=virtual",
			endpoint: "https://s3.example.org",
			region:   "us-east-1",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:      "ipv6-literal",
			raw:       "http://[::1]:9000/my-bucket/walden",
			endpoint:  "http://[::1]:9000",
			region:    "us-east-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// A root-anchored FQDN names the same host as the bare form,
			// so it must reach the same provider rule — and the same
			// region-from-host reading.
			name:      "aws-root-anchored-fqdn",
			raw:       "https://s3.eu-west-1.amazonaws.com./my-bucket/walden",
			provider:  "AWS S3",
			endpoint:  "https://s3.eu-west-1.amazonaws.com",
			region:    "eu-west-1",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
		{
			// The signing region is case-sensitive in the SigV4
			// credential scope and appears in the endpoint host, so it
			// is folded to lower case exactly like the host.
			name:     "region-query-is-lowercased",
			raw:      "s3://my-bucket/walden?region=US-EAST-2",
			provider: "AWS S3",
			endpoint: "https://s3.us-east-2.amazonaws.com",
			region:   "us-east-2",
			bucket:   "my-bucket",
			prefix:   "walden",
		},
		{
			name:      "region-environment-is-lowercased",
			raw:       "http://minio.internal:9000/my-bucket/walden",
			env:       map[string]string{store.EnvRegion: "EU-WEST-3"},
			endpoint:  "http://minio.internal:9000",
			region:    "eu-west-3",
			bucket:    "my-bucket",
			prefix:    "walden",
			pathStyle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := store.ParseJournalURL(tt.raw, envLookup(tt.env))
			if err != nil {
				t.Fatalf("ParseJournalURL(%q) failed: %v", tt.raw, err)
			}
			if j.Provider != tt.provider {
				t.Errorf("Provider = %q, want %q", j.Provider, tt.provider)
			}
			if j.Endpoint != tt.endpoint {
				t.Errorf("Endpoint = %q, want %q", j.Endpoint, tt.endpoint)
			}
			if j.Region != tt.region {
				t.Errorf("Region = %q, want %q", j.Region, tt.region)
			}
			if j.Bucket != tt.bucket {
				t.Errorf("Bucket = %q, want %q", j.Bucket, tt.bucket)
			}
			if j.Prefix != tt.prefix {
				t.Errorf("Prefix = %q, want %q", j.Prefix, tt.prefix)
			}
			if j.PathStyle != tt.pathStyle {
				t.Errorf("PathStyle = %v, want %v", j.PathStyle, tt.pathStyle)
			}
		})
	}
}

func TestParseJournalURLRefusals(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
		wantSub string
	}{
		{name: "empty", raw: "", wantErr: store.ErrInvalidJournal, wantSub: "URL is empty"},
		{name: "whitespace-only", raw: "   ", wantErr: store.ErrInvalidJournal, wantSub: "URL is empty"},
		{name: "no-scheme", raw: "my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "no scheme"},
		{name: "unsupported-scheme", raw: "ftp://host/my-bucket", wantErr: store.ErrInvalidJournal, wantSub: `unsupported URL scheme "ftp"`},
		{name: "file-scheme", raw: "file:///var/journal", wantErr: store.ErrInvalidJournal, wantSub: `unsupported URL scheme "file"`},
		{name: "no-host", raw: "s3:///walden", wantErr: store.ErrInvalidJournal, wantSub: "no host"},
		{name: "fragment", raw: "s3://my-bucket/walden#head", wantErr: store.ErrInvalidJournal, wantSub: "fragment"},
		{name: "no-bucket-in-path", raw: "https://s3.us-east-1.amazonaws.com", wantErr: store.ErrInvalidJournal, wantSub: "names no bucket"},
		{name: "no-bucket-self-hosted", raw: "http://minio.internal:9000", wantErr: store.ErrInvalidJournal, wantSub: "names no bucket"},
		{name: "unknown-query", raw: "s3://my-bucket/walden?acl=public", wantErr: store.ErrInvalidJournal, wantSub: `unknown query parameter "acl"`},
		{name: "unknown-style", raw: "s3://my-bucket/walden?style=sideways", wantErr: store.ErrInvalidJournal, wantSub: "unknown addressing style"},
		{name: "repeated-region", raw: "s3://my-bucket/walden?region=eu-west-1&region=ap-south-1", wantErr: store.ErrInvalidJournal, wantSub: `query parameter "region" is given more than once`},
		{name: "repeated-region-mixed-case", raw: "s3://my-bucket/walden?region=eu-west-1&REGION=ap-south-1", wantErr: store.ErrInvalidJournal, wantSub: `query parameter "region" is given more than once`},
		{name: "repeated-style", raw: "s3://my-bucket/walden?style=path&Style=virtual", wantErr: store.ErrInvalidJournal, wantSub: `query parameter "style" is given more than once`},
		{name: "bucket-too-short", raw: "s3://ab/walden", wantErr: store.ErrInvalidJournal, wantSub: "3 to 63 characters"},
		{name: "bucket-underscore", raw: "s3://my_bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: `bucket "my_bucket" contains "_"`},
		{name: "bucket-leading-dash", raw: "s3://-my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "start and end with"},
		{name: "bucket-trailing-dot", raw: "s3://my-bucket./walden", wantErr: store.ErrInvalidJournal, wantSub: "start and end with"},
		{name: "bucket-adjacent-dots", raw: "s3://my..bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "adjacent"},
		{name: "bucket-dot-then-dash", raw: "s3://my.-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "adjacent"},
		{name: "bucket-dash-then-dot", raw: "s3://my-.bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "adjacent"},
		{name: "prefix-parent-segment", raw: "s3://my-bucket/walden/../escape", wantErr: store.ErrInvalidJournal, wantSub: "relative path"},
		{name: "prefix-space", raw: "s3://my-bucket/wal den", wantErr: store.ErrInvalidJournal, wantSub: "prefix segment"},
		{name: "region-space", raw: "s3://my-bucket/walden?region=eu west", wantErr: store.ErrInvalidJournal, wantSub: "region"},
		{name: "userinfo-no-secret", raw: "s3://AKIAEXAMPLE@my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "no secret"},
		{name: "userinfo-no-key-id", raw: "s3://:secret@my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "no access key ID"},
		{name: "userinfo-empty", raw: "s3://@my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "empty credentials"},
		{name: "wasabi-no-cas", raw: "https://s3.eu-central-1.wasabisys.com/my-bucket/walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
		{name: "wasabi-virtual-hosted-no-cas", raw: "https://my-bucket.s3.wasabisys.com/walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
		// A root-anchored FQDN must not walk past the provider table and
		// the compare-and-swap gate behind it.
		{name: "wasabi-root-anchored-fqdn-no-cas", raw: "https://s3.wasabisys.com./my-bucket/walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
		{name: "wasabi-root-anchored-virtual-hosted-no-cas", raw: "https://my-bucket.s3.wasabisys.com./walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
		// s3:// always addresses AWS, so a port has nowhere to go. Dropping
		// it silently resolved a self-hosted endpoint to a bucket at Amazon.
		{name: "s3-scheme-with-port", raw: "s3://minio.local:9000/my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "s3:// URL carries a port"},
		// A ':' with no digits behind it is still a port that has nowhere
		// to go, and u.Port() reads "" for it.
		{name: "s3-scheme-with-empty-port", raw: "s3://my-bucket:/walden", wantErr: store.ErrInvalidJournal, wantSub: "s3:// URL carries a port"},
		{name: "dotted-bucket-cannot-be-forced-virtual-hosted", raw: "s3://my.dotted.bucket/walden?style=virtual", wantErr: store.ErrInvalidJournal, wantSub: "style=virtual conflicts with the dot in bucket"},
		// An AWS-family host with no "s3" label is not an endpoint of that
		// provider. Read as one, it resolved to a region named "com".
		{name: "aws-suffix-is-no-endpoint", raw: "https://amazonaws.com/my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: `host "amazonaws.com" names no S3 endpoint`},
		{name: "b2-suffix-is-no-endpoint", raw: "https://backblazeb2.com/my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: `host "backblazeb2.com" names no S3 endpoint`},
		// s3-accelerate fronts every region, so there is no region to read
		// and no default that is not a guess.
		{name: "accelerate-names-no-region", raw: "https://s3-accelerate.amazonaws.com/my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "fronts every region and names none"},
		{name: "accelerate-dualstack-names-no-region", raw: "https://s3-accelerate.dualstack.amazonaws.com/my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "fronts every region and names none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.ParseJournalURL(tt.raw, envLookup(creds))
			if err == nil {
				t.Fatalf("ParseJournalURL(%q) succeeded, want refusal", tt.raw)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error %v does not match %v", err, tt.wantErr)
			}
			assertOneLineRefusal(t, err)
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
			if !strings.HasPrefix(err.Error(), "invalid journal: ") {
				t.Errorf("error %q does not name the journal knob", err.Error())
			}
		})
	}
}

func TestResolveJournalCredentials(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		env        map[string]string
		wantID     string
		wantSecret string
		wantToken  string
		wantSource string
	}{
		{
			name:       "from-environment",
			raw:        "s3://my-bucket/walden",
			env:        map[string]string{store.EnvAccessKeyID: "AKIAENV", store.EnvSecretAccessKey: "envsecret"},
			wantID:     "AKIAENV",
			wantSecret: "envsecret",
			wantSource: store.EnvAccessKeyID,
		},
		{
			name: "from-environment-with-session-token",
			raw:  "s3://my-bucket/walden",
			env: map[string]string{
				store.EnvAccessKeyID:     "AKIAENV",
				store.EnvSecretAccessKey: "envsecret",
				store.EnvSessionToken:    "sessiontoken",
			},
			wantID:     "AKIAENV",
			wantSecret: "envsecret",
			wantToken:  "sessiontoken",
			wantSource: store.EnvAccessKeyID,
		},
		{
			name:       "from-url-userinfo",
			raw:        "s3://AKIAURL:urlsecret@my-bucket/walden",
			wantID:     "AKIAURL",
			wantSecret: "urlsecret",
			wantSource: "WALDEN_JOURNAL URL",
		},
		{
			name:       "url-userinfo-beats-environment",
			raw:        "s3://AKIAURL:urlsecret@my-bucket/walden",
			env:        map[string]string{store.EnvAccessKeyID: "AKIAENV", store.EnvSecretAccessKey: "envsecret"},
			wantID:     "AKIAURL",
			wantSecret: "urlsecret",
			wantSource: "WALDEN_JOURNAL URL",
		},
		{
			name:       "url-userinfo-percent-encoded-secret",
			raw:        "s3://AKIAURL:se%2Fcre%2Bt@my-bucket/walden",
			wantID:     "AKIAURL",
			wantSecret: "se/cre+t",
			wantSource: "WALDEN_JOURNAL URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := store.ResolveJournal(tt.raw, envLookup(tt.env))
			if err != nil {
				t.Fatalf("ResolveJournal(%q) failed: %v", tt.raw, err)
			}
			if j.Credentials.AccessKeyID != tt.wantID {
				t.Errorf("AccessKeyID = %q, want %q", j.Credentials.AccessKeyID, tt.wantID)
			}
			if j.Credentials.SecretAccessKey != tt.wantSecret {
				t.Errorf("SecretAccessKey = %q, want %q", j.Credentials.SecretAccessKey, tt.wantSecret)
			}
			if j.Credentials.SessionToken != tt.wantToken {
				t.Errorf("SessionToken = %q, want %q", j.Credentials.SessionToken, tt.wantToken)
			}
			if j.Credentials.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", j.Credentials.Source, tt.wantSource)
			}
		})
	}
}

func TestResolveJournalCredentialRefusals(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{
			name:    "none",
			env:     nil,
			wantSub: "no credentials in the WALDEN_JOURNAL URL or the environment",
		},
		{
			name:    "secret-without-key-id",
			env:     map[string]string{store.EnvSecretAccessKey: "envsecret"},
			wantSub: "AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is not",
		},
		{
			name:    "key-id-without-secret",
			env:     map[string]string{store.EnvAccessKeyID: "AKIAENV"},
			wantSub: "AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is not",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.ResolveJournal("s3://my-bucket/walden", envLookup(tt.env))
			if err == nil {
				t.Fatal("ResolveJournal succeeded, want refusal")
			}
			if !errors.Is(err, store.ErrNoCredentials) {
				t.Errorf("error %v does not match ErrNoCredentials", err)
			}
			assertOneLineRefusal(t, err)
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestParseJournalURLNeedsNoCredentials guards the split that lets
// --print-config check a URL on a machine that holds no secrets.
func TestParseJournalURLNeedsNoCredentials(t *testing.T) {
	j, err := store.ParseJournalURL("s3://my-bucket/walden", nil)
	if err != nil {
		t.Fatalf("ParseJournalURL with no environment failed: %v", err)
	}
	if j.Credentials.AccessKeyID != "" || j.Credentials.SecretAccessKey != "" {
		t.Errorf("ParseJournalURL resolved credentials: %+v", j.Credentials)
	}
	if j.Credentials.Source != "(none found)" {
		t.Errorf("Source = %q, want %q", j.Credentials.Source, "(none found)")
	}
}

// TestParseJournalURLNamesTheCredentialSource is the regression for a
// --print-config that reported "(unresolved)" on a machine where the AWS
// variables were set and boot would in fact succeed. The source is named; the
// secret never is.
func TestParseJournalURLNamesTheCredentialSource(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		env        map[string]string
		wantSource string
	}{
		{
			name:       "environment",
			raw:        "s3://my-bucket/walden",
			env:        map[string]string{store.EnvAccessKeyID: "AKIAENV", store.EnvSecretAccessKey: "envsecret"},
			wantSource: store.EnvAccessKeyID,
		},
		{
			name:       "url-userinfo",
			raw:        "s3://AKIAURL:urlsecret@my-bucket/walden",
			env:        nil,
			wantSource: "WALDEN_JOURNAL URL",
		},
		{
			name:       "nothing-set",
			raw:        "s3://my-bucket/walden",
			env:        nil,
			wantSource: "(none found)",
		},
		{
			name:       "half-set-environment-is-not-a-source",
			raw:        "s3://my-bucket/walden",
			env:        map[string]string{store.EnvAccessKeyID: "AKIAENV"},
			wantSource: "(none found)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := store.ParseJournalURL(tt.raw, envLookup(tt.env))
			if err != nil {
				t.Fatalf("ParseJournalURL(%q) failed: %v", tt.raw, err)
			}
			if j.Credentials.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", j.Credentials.Source, tt.wantSource)
			}
			if got := j.String(); strings.Contains(got, "envsecret") || strings.Contains(got, "urlsecret") {
				t.Errorf("Journal.String() leaked the secret: %q", got)
			}
		})
	}
}

// TestJournalStringHidesSecret keeps --print-config from printing the secret.
func TestJournalStringHidesSecret(t *testing.T) {
	j, err := store.ResolveJournal("s3://AKIAURL:topsecret@my-bucket/walden", nil)
	if err != nil {
		t.Fatalf("ResolveJournal failed: %v", err)
	}
	out := j.String()
	if strings.Contains(out, "topsecret") {
		t.Errorf("Journal.String() leaked the secret: %q", out)
	}
	for _, want := range []string{
		"journal-provider: AWS S3",
		"journal-endpoint: https://s3.us-east-1.amazonaws.com",
		"journal-region: us-east-1",
		"journal-bucket: my-bucket",
		"journal-prefix: walden",
		"journal-style: virtual-hosted",
		"journal-credentials: WALDEN_JOURNAL URL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Journal.String() = %q, want line %q", out, want)
		}
	}
}

// TestProviderNamesMatchSupportMatrix binds the host table in this package to
// the published support matrix. store must not import journal (journal is the
// layer above), so the binding is checked here rather than at compile time.
// It ranges over both tables, so drift in either direction fails: a host rule
// whose CAS bit disagrees with the matrix, and a provider the matrix marks
// unsupported that has no refusing host rule here.
func TestProviderNamesMatchSupportMatrix(t *testing.T) {
	rows := store.ProviderHostsForTest()
	if len(rows) == 0 {
		t.Fatal("the provider host table is empty")
	}

	byProvider := make(map[string]store.ProviderHostRow, len(rows))
	for _, row := range rows {
		byProvider[row.Provider] = row
	}

	// Every host rule here names a provider the matrix knows, agrees with
	// the matrix about compare-and-swap, and behaves that way at boot.
	for _, row := range rows {
		t.Run("host-table/"+row.Provider, func(t *testing.T) {
			info, ok := journal.LookupProvider(row.Provider)
			if !ok {
				t.Fatalf("provider %q is not in the support matrix", row.Provider)
			}
			if info.Name != row.Provider {
				t.Fatalf("provider %q resolves to matrix entry %q", row.Provider, info.Name)
			}
			wantCAS := journal.ValidateProviderCAS(row.Provider) == nil
			if row.CAS != wantCAS {
				t.Errorf("host table says cas=%v for %q, support matrix says %v (status %q)", row.CAS, row.Provider, wantCAS, info.Status)
			}

			// The bare suffix is a host of the right provider family,
			// which is all this assertion needs. It is not necessarily a
			// usable endpoint — https://amazonaws.com names no S3
			// endpoint and is refused as such — so the only thing
			// checked here is the compare-and-swap bit. Whether a host
			// resolves, and to what, is TestParseJournalURLLocations.
			raw := "https://" + row.Suffix + "/my-bucket/walden"
			_, err := store.ParseJournalURL(raw, envLookup(creds))
			refused := errors.Is(err, store.ErrProviderUnsupported)
			if refused == row.CAS {
				t.Errorf("ParseJournalURL(%q) refused=%v, want %v (err: %v)", raw, refused, !row.CAS, err)
			}
		})
	}

	// Every provider the matrix marks unsupported has a refusing host rule
	// here, so it is refused at boot rather than on the first push.
	for _, info := range journal.ProviderSupportMatrix {
		if info.Status != journal.ProviderUnsupported {
			continue
		}
		t.Run("matrix/"+info.Name, func(t *testing.T) {
			row, ok := byProvider[info.Name]
			if !ok {
				t.Fatalf("support matrix marks %q unsupported, but internal/store has no host rule for it: walden would accept it at boot", info.Name)
			}
			if row.CAS {
				t.Errorf("support matrix marks %q unsupported, but its host rule says cas=true", info.Name)
			}
		})
	}
}

// TestJournalRefusalsHideTheSecret is the regression for the leak that let a
// WALDEN_JOURNAL value reach stderr with its userinfo intact.
//
// The first round of this test scoped itself to URLs net/url refuses to parse,
// and that scoping was the bug: those are the safe half. The dangerous half is
// the URL net/url parses happily, because an unencoded '/', '?', or '#' in the
// credentials ended the authority before the '@' and moved the tail of the
// secret into a port, a path, or a query — fields the refusals then quoted
// verbatim. Both halves are here now.
func TestJournalRefusalsHideTheSecret(t *testing.T) {
	const (
		keyID  = "PUBLICKEYIDEXAMPLE"
		secret = "zzTOPSECRETzz"
	)

	raws := []struct {
		name string
		raw  string
	}{
		// net/url returns an error: the secret is still in the userinfo.
		{"invalid-port", "s3://" + keyID + ":" + secret + "@bucket:80x/p"},
		{"control-character", "s3://" + keyID + ":" + secret + "@bucket/p\x7f"},
		{"unclosed-ipv6-literal", "https://" + keyID + ":" + secret + "@[::1/my-bucket/walden"},
		{"bad-escape-in-query", "s3://" + keyID + ":" + secret + "@my-bucket/walden?region=%" + secret},
		{"bad-escape-in-userinfo", "s3://" + keyID + ":se%" + secret + "@my-bucket/walden"},

		// net/url returns no error: the secret has been relocated. Each of
		// these was quoted back in full by a refusal.
		{"slash-in-secret-lands-in-the-prefix", "s3://" + keyID + ":/" + secret + "@bucket/prefix"},
		{"slash-in-secret-lands-in-the-bucket", "https://" + keyID + ":/" + secret + "@s3.eu-west-1.amazonaws.com/bucket/prefix"},
		{"digits-before-the-slash-land-in-the-port", "s3://" + keyID + ":012/" + secret + "@bucket/prefix"},
		{"question-mark-in-secret-lands-in-the-query", "s3://" + keyID + ":?" + secret + "@bucket/prefix"},
		{"hash-in-secret-lands-in-the-fragment", "s3://" + keyID + ":#" + secret + "@bucket/prefix"},
		{"slash-in-key-id-lands-in-the-prefix", "s3://AKIA/" + keyID + ":" + secret + "@bucket/prefix"},
		{"encoded-delimiters-land-in-the-host", "s3://" + keyID + "%3A" + secret + "%40bucket/prefix"},
	}

	// net/url's escape errors quote the three characters around a bad '%',
	// so a leak can be a fragment rather than the whole secret.
	forbidden := []string{keyID, secret, secret[:3]}

	for _, tt := range raws {
		t.Run(tt.name, func(t *testing.T) {
			for _, entry := range []struct {
				name string
				fn   func(string, func(string) (string, bool)) (*store.Journal, error)
			}{
				{"ParseJournalURL", store.ParseJournalURL},
				{"ResolveJournal", store.ResolveJournal},
			} {
				_, err := entry.fn(tt.raw, envLookup(creds))
				if err == nil {
					t.Fatalf("%s succeeded, want refusal", entry.name)
				}
				assertOneLineRefusal(t, err)
				for _, leak := range forbidden {
					if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(leak)) {
						t.Errorf("%s leaked %q: %q", entry.name, leak, err.Error())
					}
				}
			}
		})
	}
}

// TestBucketWithAdjacentHyphensIsAccepted is the regression for a refusal that
// told an operator their valid bucket name was invalid. The AWS general-purpose
// bucket rules prohibit two adjacent periods, and a period next to a hyphen;
// two adjacent hyphens are legal, and "acme--journal" is a real name on S3,
// GCS, R2, and MinIO alike. walden refused to boot against one.
func TestBucketWithAdjacentHyphensIsAccepted(t *testing.T) {
	accepted := []struct {
		name   string
		raw    string
		bucket string
	}{
		{"s3-shorthand", "s3://acme--journal/walden", "acme--journal"},
		{"path-style", "https://s3.eu-west-1.amazonaws.com/acme--journal/walden", "acme--journal"},
		{"self-hosted", "http://minio.internal:9000/acme--journal/walden", "acme--journal"},
		{"three-hyphens", "s3://acme---journal/walden", "acme---journal"},
	}
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			j, err := store.ParseJournalURL(tt.raw, envLookup(creds))
			if err != nil {
				t.Fatalf("ParseJournalURL(%q) refused a legal bucket name: %v", tt.raw, err)
			}
			if j.Bucket != tt.bucket {
				t.Errorf("Bucket = %q, want %q", j.Bucket, tt.bucket)
			}
		})
	}

	// The rule the hyphens were standing in for is still enforced: a period
	// may not sit beside a period or a hyphen.
	for _, raw := range []string{
		"s3://acme..journal/walden",
		"s3://acme.-journal/walden",
		"s3://acme-.journal/walden",
	} {
		if _, err := store.ParseJournalURL(raw, envLookup(creds)); err == nil {
			t.Errorf("ParseJournalURL(%q) accepted a period adjacent to a period or hyphen", raw)
		}
	}
}

// TestS3SchemeBucketKeepsItsCase is the regression for a URL that silently
// addressed a bucket other than the one written. Under s3:// the host is a
// bucket name, not a host, and folding it to lower case made
// s3://BUCKET/walden resolve to a bucket called "bucket" — while the identical
// name written path-style was refused for the uppercase. Same bucket, two
// spellings, two outcomes, and the accepted one rewrote the operator's value.
// walden never guesses: both spellings refuse.
func TestS3SchemeBucketKeepsItsCase(t *testing.T) {
	const pathStyle = "https://s3.eu-west-1.amazonaws.com/BUCKET/walden"
	const shorthand = "s3://BUCKET/walden"

	for _, raw := range []string{shorthand, pathStyle} {
		_, err := store.ParseJournalURL(raw, envLookup(creds))
		if err == nil {
			t.Fatalf("ParseJournalURL(%q) accepted an uppercase bucket name", raw)
		}
		if !errors.Is(err, store.ErrInvalidJournal) {
			t.Errorf("ParseJournalURL(%q) error %v does not match ErrInvalidJournal", raw, err)
		}
		assertOneLineRefusal(t, err)
		const want = `bucket "BUCKET" contains "B"`
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ParseJournalURL(%q) error %q does not contain %q", raw, err.Error(), want)
		}
	}

	// The host is still folded for the provider table, which matches
	// hostnames and is case-insensitive. This is the case round 3 verified:
	// an uppercase, root-anchored Wasabi host must still reach the
	// compare-and-swap gate.
	_, err := store.ParseJournalURL("https://S3.WASABISYS.COM./my-bucket/walden", envLookup(creds))
	if !errors.Is(err, store.ErrProviderUnsupported) {
		t.Errorf("an uppercase Wasabi host gave %v, want the compare-and-swap refusal", err)
	}
}

// assertOneLineRefusal checks the operator-facing refusal convention.
func assertOneLineRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, &refusal.Refusal{}) {
		t.Errorf("error %v is not a *refusal.Refusal", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal %q is not a single line", err.Error())
	}
}
