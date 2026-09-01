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
			name:     "aws-virtual-hosted-dotted-bucket",
			raw:      "https://my.dotted.bucket.s3.amazonaws.com/walden",
			provider: "AWS S3",
			endpoint: "https://s3.amazonaws.com",
			region:   "us-east-1",
			bucket:   "my.dotted.bucket",
			prefix:   "walden",
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
		{name: "style-conflict", raw: "https://my-bucket.s3.amazonaws.com/walden?style=path", wantErr: store.ErrInvalidJournal, wantSub: "conflicts with bucket"},
		{name: "bucket-too-short", raw: "s3://ab/walden", wantErr: store.ErrInvalidJournal, wantSub: "3 to 63 characters"},
		{name: "bucket-underscore", raw: "s3://my_bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: `bucket "my_bucket" contains "_"`},
		{name: "bucket-leading-dash", raw: "s3://-my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "start and end with"},
		{name: "bucket-trailing-dot", raw: "s3://my-bucket./walden", wantErr: store.ErrInvalidJournal, wantSub: "start and end with"},
		{name: "bucket-adjacent-dots", raw: "s3://my..bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "adjacent"},
		{name: "prefix-parent-segment", raw: "s3://my-bucket/walden/../escape", wantErr: store.ErrInvalidJournal, wantSub: "relative path"},
		{name: "prefix-space", raw: "s3://my-bucket/wal den", wantErr: store.ErrInvalidJournal, wantSub: "prefix segment"},
		{name: "region-space", raw: "s3://my-bucket/walden?region=eu west", wantErr: store.ErrInvalidJournal, wantSub: "region"},
		{name: "userinfo-no-secret", raw: "s3://AKIAEXAMPLE@my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "no secret"},
		{name: "userinfo-no-key-id", raw: "s3://:secret@my-bucket/walden", wantErr: store.ErrInvalidJournal, wantSub: "no access key ID"},
		{name: "wasabi-no-cas", raw: "https://s3.eu-central-1.wasabisys.com/my-bucket/walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
		{name: "wasabi-virtual-hosted-no-cas", raw: "https://my-bucket.s3.wasabisys.com/walden", wantErr: store.ErrProviderUnsupported, wantSub: "compare-and-swap"},
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
	if j.Credentials.AccessKeyID != "" || j.Credentials.Source != "" {
		t.Errorf("ParseJournalURL resolved credentials: %+v", j.Credentials)
	}
}

func TestJournalKeyAndObjectURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		key     string
		wantKey string
		wantURL string
	}{
		{
			name:    "path-style-with-prefix",
			raw:     "http://minio.internal:9000/my-bucket/walden",
			key:     "tx/000000000001.json",
			wantKey: "walden/tx/000000000001.json",
			wantURL: "http://minio.internal:9000/my-bucket/walden/tx/000000000001.json",
		},
		{
			name:    "path-style-bucket-root",
			raw:     "http://minio.internal:9000/my-bucket",
			key:     "tx/000000000001.json",
			wantKey: "tx/000000000001.json",
			wantURL: "http://minio.internal:9000/my-bucket/tx/000000000001.json",
		},
		{
			name:    "virtual-hosted-with-prefix",
			raw:     "https://my-bucket.s3.eu-west-1.amazonaws.com/walden",
			key:     "tx/000000000001.json",
			wantKey: "walden/tx/000000000001.json",
			wantURL: "https://my-bucket.s3.eu-west-1.amazonaws.com/walden/tx/000000000001.json",
		},
		{
			name:    "virtual-hosted-shorthand",
			raw:     "s3://my-bucket/backups/walden",
			key:     "packs/abc123.pack",
			wantKey: "backups/walden/packs/abc123.pack",
			wantURL: "https://my-bucket.s3.us-east-1.amazonaws.com/backups/walden/packs/abc123.pack",
		},
		{
			name:    "r2-path-style",
			raw:     "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden",
			key:     "tx/000000000002.json",
			wantKey: "walden/tx/000000000002.json",
			wantURL: "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden/tx/000000000002.json",
		},
		{
			name:    "leading-slash-on-key",
			raw:     "s3://my-bucket/walden",
			key:     "/tx/000000000003.json",
			wantKey: "walden/tx/000000000003.json",
			wantURL: "https://my-bucket.s3.us-east-1.amazonaws.com/walden/tx/000000000003.json",
		},
		{
			name:    "empty-key-is-the-list-prefix",
			raw:     "s3://my-bucket/walden",
			key:     "",
			wantKey: "walden/",
			wantURL: "https://my-bucket.s3.us-east-1.amazonaws.com/walden/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := store.ParseJournalURL(tt.raw, nil)
			if err != nil {
				t.Fatalf("ParseJournalURL(%q) failed: %v", tt.raw, err)
			}
			if got := j.Key(tt.key); got != tt.wantKey {
				t.Errorf("Key(%q) = %q, want %q", tt.key, got, tt.wantKey)
			}
			if got := j.ObjectURL(tt.key); got != tt.wantURL {
				t.Errorf("ObjectURL(%q) = %q, want %q", tt.key, got, tt.wantURL)
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

// TestProviderNamesMatchSupportMatrix ties the host table in this package to
// the published support matrix. store must not import journal (journal is the
// layer above), so the tie is checked here instead of at compile time.
func TestProviderNamesMatchSupportMatrix(t *testing.T) {
	tests := []struct {
		raw          string
		wantProvider string
		wantStatus   journal.ProviderStatus
	}{
		{raw: "s3://my-bucket/walden", wantProvider: "AWS S3", wantStatus: journal.ProviderSupported},
		{raw: "https://a1b2c3.r2.cloudflarestorage.com/my-bucket/walden", wantProvider: "Cloudflare R2", wantStatus: journal.ProviderSupported},
		{raw: "https://storage.googleapis.com/my-bucket/walden", wantProvider: "Google Cloud Storage", wantStatus: journal.ProviderSupported},
		{raw: "https://s3.us-west-004.backblazeb2.com/my-bucket/walden", wantProvider: "Backblaze B2", wantStatus: journal.ProviderSupported},
		{raw: "https://myaccount.blob.core.windows.net/my-container/walden", wantProvider: "Azure Blob Storage", wantStatus: journal.ProviderConditional},
	}

	for _, tt := range tests {
		t.Run(tt.wantProvider, func(t *testing.T) {
			j, err := store.ParseJournalURL(tt.raw, nil)
			if err != nil {
				t.Fatalf("ParseJournalURL(%q) failed: %v", tt.raw, err)
			}
			if j.Provider != tt.wantProvider {
				t.Fatalf("Provider = %q, want %q", j.Provider, tt.wantProvider)
			}
			info, ok := journal.LookupProvider(j.Provider)
			if !ok {
				t.Fatalf("provider %q is not in the support matrix", j.Provider)
			}
			if info.Status != tt.wantStatus {
				t.Errorf("support matrix status for %q = %q, want %q", j.Provider, info.Status, tt.wantStatus)
			}
		})
	}

	// Every provider the matrix marks unsupported must be refused at boot,
	// not on the first push.
	if err := journal.ValidateProviderCAS("Wasabi"); err == nil {
		t.Fatal("support matrix no longer marks Wasabi unsupported; update providerHosts")
	}
	if _, err := store.ParseJournalURL("https://s3.us-east-1.wasabisys.com/my-bucket/walden", nil); !errors.Is(err, store.ErrProviderUnsupported) {
		t.Errorf("Wasabi URL was not refused at boot: %v", err)
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
