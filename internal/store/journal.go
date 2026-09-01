package store

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// This file resolves the journal knob. One URL is the whole journal
// configuration, so WALDEN_JOURNAL has to carry endpoint, region, bucket, and
// prefix for every provider in the support matrix (see spec/journal/v1,
// section 11.2), in both addressing styles.
//
// Accepted forms:
//
//	s3://bucket/prefix                              AWS shorthand, virtual-hosted
//	https://s3.eu-west-1.amazonaws.com/bucket/prefix path-style
//	https://bucket.s3.eu-west-1.amazonaws.com/prefix virtual-hosted
//	https://<account>.r2.cloudflarestorage.com/bucket/prefix
//	https://bucket.<account>.r2.cloudflarestorage.com/prefix
//	https://storage.googleapis.com/bucket/prefix
//	https://bucket.storage.googleapis.com/prefix
//	https://s3.us-west-004.backblazeb2.com/bucket/prefix
//	https://<account>.blob.core.windows.net/container/prefix
//	http://minio.internal:9000/bucket/prefix        MinIO, Ceph RGW, Garage
//
// A host walden does not recognise is read path-style, which is the default
// for every self-hosted S3 implementation. Two query parameters, and only two,
// may override what the host implies: region and style (path or virtual).
//
// Everything here happens at configuration time. A malformed URL stops walden
// at boot with one line, not on the first push. Nothing here talks to object
// storage; see ResolveJournal for the credentials it will eventually sign with.

// Errors returned by journal resolution. Each is returned wrapped in a
// *refusal.Refusal, so what an operator sees is a single line.
var (
	// ErrInvalidJournal indicates a WALDEN_JOURNAL value walden cannot resolve.
	ErrInvalidJournal = errors.New("invalid journal URL")

	// ErrProviderUnsupported indicates a provider without compare-and-swap.
	ErrProviderUnsupported = errors.New("storage provider does not support compare-and-swap (CAS) conditional writes")

	// ErrNoCredentials indicates that no journal credentials could be resolved.
	ErrNoCredentials = errors.New("no journal credentials")
)

// DefaultRegion is used when neither the URL, the endpoint host, the provider,
// nor the environment names one. Self-hosted S3 implementations ignore the
// region but still require one in the signature.
const DefaultRegion = "us-east-1"

// Environment variables walden reads for credentials and region. They are AWS
// conventions, deliberately not walden knobs.
const (
	EnvAccessKeyID     = "AWS_ACCESS_KEY_ID"
	EnvSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	EnvSessionToken    = "AWS_SESSION_TOKEN"
	EnvRegion          = "AWS_REGION"
	EnvDefaultRegion   = "AWS_DEFAULT_REGION"
)

// Credentials are the static object-storage credentials walden signs with.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// Source names where the credentials came from, or would come from,
	// for --print-config. It never contains the secret.
	Source string
}

// Journal is the resolved object-storage location of the journal: the four
// things one WALDEN_JOURNAL URL has to carry, plus how to address them.
type Journal struct {
	// Provider is the name from the support matrix in spec/journal/v1,
	// or "" for a host walden does not recognise.
	Provider string

	// Endpoint is scheme://host[:port] with no bucket label and no path.
	// For virtual-hosted addressing the bucket label is prepended to the
	// host at request time.
	Endpoint string

	// Region is the signing region.
	Region string

	// Bucket is the bucket (Azure: container) holding the journal.
	Bucket string

	// Prefix is the key prefix within the bucket, with no leading or
	// trailing slash. Empty means the journal lives at the bucket root.
	Prefix string

	// PathStyle reports whether requests address the bucket in the path
	// rather than in the hostname.
	PathStyle bool

	// Credentials holds the resolved secret only for a Journal that came
	// from ResolveJournal. ParseJournalURL fills in Source either way.
	Credentials Credentials
}

// providerHost describes how to read a URL for one known provider family.
type providerHost struct {
	// suffix is the trailing part of the host that identifies the provider.
	suffix string

	// provider is the name as it appears in the support matrix.
	provider string

	// endpointLabels is the number of dot-separated labels in the bare
	// endpoint host; any label to the left of those is a bucket, meaning
	// the URL is virtual-hosted. -1 means the endpoint host begins at the
	// rightmost "s3" or "s3-<region>" label, the AWS-style layout.
	endpointLabels int

	// fixedRegion is the provider's only region, if it has one. It beats
	// the environment so a stray AWS_REGION cannot break signing.
	fixedRegion string

	// cas reports whether the provider supports the conditional writes the
	// journal is built on. A provider without them is refused at boot.
	cas bool
}

// providerHosts mirrors the support matrix in spec/journal/v1 section 11.2 and
// internal/journal.ProviderSupportMatrix. MinIO, Ceph RGW, and Garage are
// self-hosted under operator-chosen hostnames; they are the unrecognised,
// path-style default rather than entries here.
var providerHosts = []providerHost{
	{suffix: "amazonaws.com", provider: "AWS S3", endpointLabels: -1, cas: true},
	{suffix: "backblazeb2.com", provider: "Backblaze B2", endpointLabels: -1, cas: true},
	{suffix: "wasabisys.com", provider: "Wasabi", endpointLabels: -1, cas: false},
	{suffix: "storage.googleapis.com", provider: "Google Cloud Storage", endpointLabels: 3, fixedRegion: "auto", cas: true},
	{suffix: "r2.cloudflarestorage.com", provider: "Cloudflare R2", endpointLabels: 4, fixedRegion: "auto", cas: true},
	{suffix: "blob.core.windows.net", provider: "Azure Blob Storage", endpointLabels: 5, fixedRegion: "auto", cas: true},
}

// ResolveJournal resolves a WALDEN_JOURNAL value into a complete Journal:
// endpoint, region, bucket, prefix, and credentials. It is the boot-path entry
// point. Every failure is a single-line refusal naming the journal knob.
//
// Credentials resolve through exactly this order, first hit wins:
//
//  1. Userinfo in the WALDEN_JOURNAL URL: s3://ACCESS_KEY:SECRET@bucket/prefix.
//     Percent-encode any reserved character in the secret. This keeps the
//     promise that one URL is the whole journal configuration.
//  2. The conventional AWS environment variables AWS_ACCESS_KEY_ID and
//     AWS_SECRET_ACCESS_KEY, plus AWS_SESSION_TOKEN when it is set.
//  3. Nothing: walden refuses at boot, in one line.
//
// Those AWS_* variables are conventions walden reads, not walden knobs. There
// is no sixth knob here and no WALDEN_* credential variable: the configuration
// surface remains the five knobs in ARCHITECTURE.md. Nor does walden consult
// the shared credentials file, instance metadata, ECS task roles, or web
// identity tokens. Static credentials only, from the two places above.
func ResolveJournal(raw string, lookupEnv func(string) (string, bool)) (*Journal, error) {
	j, err := ParseJournalURL(raw, lookupEnv)
	if err != nil {
		return nil, err
	}
	if j.Credentials.AccessKeyID == "" {
		creds, err := credentialsFromEnv(lookupEnv)
		if err != nil {
			return nil, err
		}
		j.Credentials = creds
	}
	return j, nil
}

// ParseJournalURL resolves the location half of a WALDEN_JOURNAL value:
// provider, endpoint, region, bucket, prefix, and addressing style. It picks up
// credentials embedded in the URL but does not require any, so that
// --print-config can check a URL on a machine that holds no secrets. When the
// URL carries none it still names where ResolveJournal would find them, in
// Credentials.Source, so --print-config does not report an unresolved
// configuration that would in fact boot.
//
// The region resolves through this order, first hit wins: the region query
// parameter, then the region named in the endpoint host, then the provider's
// only region for the providers that have one, then AWS_REGION, then
// AWS_DEFAULT_REGION, then DefaultRegion. A provider with a single region beats
// the environment so that a stray AWS_REGION cannot break signing.
func ParseJournalURL(raw string, lookupEnv func(string) (string, bool)) (*Journal, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, refuseJournal("URL is empty", "set WALDEN_JOURNAL to a URL such as s3://bucket/prefix")
	}

	u, err := url.Parse(raw)
	if err != nil {
		// net/url's parse errors quote the whole URL back, userinfo and
		// all. The journal URL may carry an object-storage secret and
		// this line goes to stderr, so the URL is not echoed.
		return nil, refuseJournal(
			"URL is malformed; it is not echoed because it may carry credentials",
			"expected a URL such as s3://bucket/prefix")
	}
	if u.Fragment != "" {
		return nil, refuseJournal("URL carries a fragment", "remove everything from the '#' onwards")
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "s3", "https", "http":
	case "":
		return nil, refuseJournal("URL has no scheme", "expected s3://, https://, or http://")
	default:
		return nil, refuseJournal(fmt.Sprintf("unsupported URL scheme %q", u.Scheme), "expected s3://, https://, or http://")
	}

	region, style, err := journalQuery(u)
	if err != nil {
		return nil, err
	}

	// The s3:// shorthand always resolves to an AWS HTTPS endpoint.
	endpointScheme := scheme
	if scheme == "s3" {
		endpointScheme = "https"
	}

	host := strings.ToLower(u.Hostname())
	if scheme != "s3" {
		// A root-anchored FQDN ("s3.wasabisys.com.") names the same host
		// as the bare form. Strip the root dot so the provider table —
		// and the compare-and-swap gate behind it — sees one spelling.
		// Under s3:// the host is a bucket name, not a host, so a
		// trailing dot there stays and fails the bucket rules.
		host = strings.TrimRight(host, ".")
	}
	if host == "" {
		return nil, refuseJournal("URL has no host", "expected s3://bucket/prefix or https://endpoint/bucket/prefix")
	}

	j := &Journal{}
	segments := pathSegments(u.Path)

	if scheme == "s3" {
		// s3://bucket/prefix: the host is the bucket and AWS is implied.
		// A port has nowhere to go — the endpoint is AWS's — and silently
		// dropping it would resolve s3://minio.local:9000/bucket/walden
		// to a bucket named "minio.local" at Amazon.
		if u.Port() != "" {
			return nil, refuseJournal(
				fmt.Sprintf("s3:// URL carries port %q, but s3:// always addresses AWS", u.Port()),
				"for a self-hosted endpoint use http(s)://host:port/bucket/prefix")
		}
		j.Provider = "AWS S3"
		j.Bucket = host
		j.Prefix = strings.Join(segments, "/")
		j.Region = resolveRegion(region, envValue(lookupEnv, EnvRegion), envValue(lookupEnv, EnvDefaultRegion), DefaultRegion)
		j.Endpoint = "https://s3." + j.Region + ".amazonaws.com"
		j.PathStyle = style == "path"
	} else {
		rule, known := matchProviderHost(host)
		bucketLabel, endpointHost := "", host
		if known {
			bucketLabel, endpointHost = rule.split(host)
		}
		j.Provider = rule.provider

		if !rule.cas {
			return nil, refusal.RefuseWithCause(
				"invalid journal",
				fmt.Sprintf("%s does not support compare-and-swap (CAS) conditional writes", rule.provider),
				"see the provider support matrix in spec/journal/v1",
				ErrProviderUnsupported,
			)
		}

		switch style {
		case "path":
			if bucketLabel != "" {
				return nil, refuseJournal(
					fmt.Sprintf("style=path conflicts with bucket %q in the hostname", bucketLabel),
					"drop the bucket label from the host, or drop style=path")
			}
			j.PathStyle = true
		case "virtual":
			j.PathStyle = false
		default:
			j.PathStyle = bucketLabel == ""
		}

		if j.PathStyle {
			if len(segments) == 0 {
				return nil, refuseJournal("URL names no bucket", "expected https://endpoint/bucket/prefix")
			}
			j.Bucket = segments[0]
			j.Prefix = strings.Join(segments[1:], "/")
		} else {
			if bucketLabel == "" {
				// style=virtual on a host that carries no bucket label:
				// the bucket is still the first path segment, and the
				// client will move it into the hostname.
				if len(segments) == 0 {
					return nil, refuseJournal("URL names no bucket", "expected https://bucket.endpoint/prefix")
				}
				j.Bucket = segments[0]
				j.Prefix = strings.Join(segments[1:], "/")
			} else {
				j.Bucket = bucketLabel
				j.Prefix = strings.Join(segments, "/")
			}
		}

		j.Endpoint = scheme + "://" + hostPort(endpointHost, u.Port())
		j.Region = resolveRegion(
			region,
			rule.regionFromHost(endpointHost),
			rule.fixedRegion,
			envValue(lookupEnv, EnvRegion),
			envValue(lookupEnv, EnvDefaultRegion),
			DefaultRegion,
		)
	}

	if err := validateBucket(j.Bucket); err != nil {
		return nil, err
	}

	// A bucket name containing a dot cannot be addressed virtual-hosted over
	// HTTPS: provider wildcard certificates are one label deep, so
	// my.dotted.bucket.s3.<region>.amazonaws.com fails verification.
	// Path-style is the only shape that can work, and is what every S3
	// client falls back to. Over plain HTTP there is no certificate to
	// match, so the operator's choice stands.
	if !j.PathStyle && endpointScheme == "https" && strings.Contains(j.Bucket, ".") {
		if style == "virtual" {
			return nil, refuseJournal(
				fmt.Sprintf("style=virtual conflicts with the dot in bucket %q", j.Bucket),
				"a dotted bucket name cannot match an HTTPS wildcard certificate; drop style=virtual")
		}
		j.PathStyle = true
	}

	if err := validatePrefix(j.Prefix); err != nil {
		return nil, err
	}
	if err := validateRegion(j.Region); err != nil {
		return nil, err
	}

	creds, err := credentialsFromURL(u)
	if err != nil {
		return nil, err
	}
	if creds.Source == "" {
		// No credentials in the URL. Name where ResolveJournal would find
		// them, without reading them, so --print-config tells the truth
		// about a boot that will succeed.
		creds.Source = envCredentialSource(lookupEnv)
	}
	j.Credentials = creds

	return j, nil
}

// journalQuery reads the two query parameters walden accepts and refuses any other.
func journalQuery(u *url.URL) (region, style string, err error) {
	q, parseErr := url.ParseQuery(u.RawQuery)
	if parseErr != nil {
		// Same reason as the URL itself: the parse error quotes the input
		// back, and no part of a journal URL is echoed.
		return "", "", refuseJournal("query string is malformed", "the only query parameters are region and style")
	}
	for key := range q {
		switch key {
		case "region", "style":
		default:
			return "", "", refuseJournal(fmt.Sprintf("unknown query parameter %q", key), "the only query parameters are region and style")
		}
	}
	region = strings.TrimSpace(q.Get("region"))
	style = strings.TrimSpace(strings.ToLower(q.Get("style")))
	switch style {
	case "", "path", "virtual":
	default:
		return "", "", refuseJournal(fmt.Sprintf("unknown addressing style %q", style), "style must be path or virtual")
	}
	return region, style, nil
}

// matchProviderHost returns the longest-suffix provider rule matching host.
// An unrecognised host gets a rule that says: path-style, no fixed region, and
// no provider name to check against the support matrix.
func matchProviderHost(host string) (providerHost, bool) {
	best := providerHost{cas: true}
	found := false
	for _, rule := range providerHosts {
		if host != rule.suffix && !strings.HasSuffix(host, "."+rule.suffix) {
			continue
		}
		if !found || len(rule.suffix) > len(best.suffix) {
			best, found = rule, true
		}
	}
	return best, found
}

// split separates a bucket label from the bare endpoint host. An empty bucket
// means the URL is path-style.
func (r providerHost) split(host string) (bucket, endpoint string) {
	labels := strings.Split(host, ".")
	if r.endpointLabels < 0 {
		// Scan from the right so a bucket named "s3-backups" is not
		// mistaken for the start of the endpoint host.
		for i := len(labels) - 1; i >= 0; i-- {
			if labels[i] == "s3" || strings.HasPrefix(labels[i], "s3-") {
				return strings.Join(labels[:i], "."), strings.Join(labels[i:], ".")
			}
		}
		return "", host
	}
	if len(labels) <= r.endpointLabels {
		return "", host
	}
	n := len(labels) - r.endpointLabels
	return strings.Join(labels[:n], "."), strings.Join(labels[n:], ".")
}

// regionFromHost returns the region named in a bare endpoint host, if any.
// It recognises the AWS-style layouts s3.<region>.<suffix>, s3-<region>.<suffix>,
// and s3.dualstack.<region>.<suffix>, which Backblaze B2 and Wasabi share.
func (r providerHost) regionFromHost(endpoint string) string {
	if r.endpointLabels >= 0 {
		return ""
	}
	middle := strings.Split(strings.TrimSuffix(endpoint, "."+r.suffix), ".")
	if len(middle) == 0 || middle[0] == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(middle[0], "s3-"); ok && rest != "" {
		return rest
	}
	for _, label := range middle[1:] {
		if label != "dualstack" && label != "" {
			return label
		}
	}
	return ""
}

// credentialsFromURL reads credentials embedded in the journal URL's userinfo.
func credentialsFromURL(u *url.URL) (Credentials, error) {
	if u.User == nil {
		return Credentials{}, nil
	}
	id := u.User.Username()
	secret, _ := u.User.Password()
	switch {
	case id == "" && secret == "":
		return Credentials{}, refuseJournal("URL carries empty credentials", "drop the '@', or use s3://ACCESS_KEY:SECRET@bucket/prefix")
	case id == "":
		return Credentials{}, refuseJournal("URL carries a secret with no access key ID", "use s3://ACCESS_KEY:SECRET@bucket/prefix")
	case secret == "":
		return Credentials{}, refuseJournal("URL carries an access key ID with no secret", "use s3://ACCESS_KEY:SECRET@bucket/prefix, percent-encoding reserved characters")
	}
	return Credentials{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		Source:          "WALDEN_JOURNAL URL",
	}, nil
}

// credentialsFromEnv reads the conventional AWS credential variables.
func credentialsFromEnv(lookupEnv func(string) (string, bool)) (Credentials, error) {
	id := envValue(lookupEnv, EnvAccessKeyID)
	secret := envValue(lookupEnv, EnvSecretAccessKey)
	switch {
	case id == "" && secret == "":
		return Credentials{}, refusal.RefuseWithCause(
			"invalid journal",
			"no credentials in the WALDEN_JOURNAL URL or the environment",
			"set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or embed them in the URL",
			ErrNoCredentials,
		)
	case id == "":
		return Credentials{}, refusal.RefuseWithCause(
			"invalid journal",
			"AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is not",
			"set both, or embed both in the WALDEN_JOURNAL URL",
			ErrNoCredentials,
		)
	case secret == "":
		return Credentials{}, refusal.RefuseWithCause(
			"invalid journal",
			"AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is not",
			"set both, or embed both in the WALDEN_JOURNAL URL",
			ErrNoCredentials,
		)
	}
	return Credentials{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		SessionToken:    envValue(lookupEnv, EnvSessionToken),
		Source:          EnvAccessKeyID,
	}, nil
}

// envCredentialSource names the environment credentials walden would sign
// with, without printing any part of the secret. --print-config prints the
// source rather than the credentials, so a URL can be checked on a machine
// that holds no secrets.
func envCredentialSource(lookupEnv func(string) (string, bool)) string {
	if envValue(lookupEnv, EnvAccessKeyID) != "" && envValue(lookupEnv, EnvSecretAccessKey) != "" {
		return EnvAccessKeyID
	}
	return "(none found)"
}

// String renders the resolved journal for walden serve --print-config.
// It never prints the secret.
func (j *Journal) String() string {
	style := "virtual-hosted"
	if j.PathStyle {
		style = "path"
	}
	provider := j.Provider
	if provider == "" {
		provider = "(unrecognised host, assuming S3-compatible)"
	}
	prefix := j.Prefix
	if prefix == "" {
		prefix = "(bucket root)"
	}
	credentials := j.Credentials.Source
	if credentials == "" {
		credentials = "(unresolved)"
	}
	return fmt.Sprintf(
		"journal-provider: %s\njournal-endpoint: %s\njournal-region: %s\njournal-bucket: %s\njournal-prefix: %s\njournal-style: %s\njournal-credentials: %s",
		provider, j.Endpoint, j.Region, j.Bucket, prefix, style, credentials,
	)
}

// pathSegments splits a URL path into its non-empty segments.
func pathSegments(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// hostPort reattaches a port to a host, bracketing IPv6 literals.
func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// validateBucket applies the S3 bucket naming rules, which every provider in
// the support matrix enforces some subset of.
func validateBucket(bucket string) error {
	if bucket == "" {
		return refuseJournal("URL names no bucket", "expected s3://bucket/prefix or https://endpoint/bucket/prefix")
	}
	if len(bucket) < 3 || len(bucket) > 63 {
		return refuseJournal(fmt.Sprintf("bucket %q is not 3 to 63 characters", bucket), "use a valid S3 bucket name")
	}
	for i := 0; i < len(bucket); i++ {
		c := bucket[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.':
			if i == 0 || i == len(bucket)-1 {
				return refuseJournal(fmt.Sprintf("bucket %q must start and end with a letter or digit", bucket), "use a valid S3 bucket name")
			}
			if bucket[i-1] == '-' || bucket[i-1] == '.' {
				return refuseJournal(fmt.Sprintf("bucket %q has adjacent '.' or '-' characters", bucket), "use a valid S3 bucket name")
			}
		default:
			return refuseJournal(fmt.Sprintf("bucket %q contains %q", bucket, string(c)), "bucket names hold only lowercase letters, digits, '-', and '.'")
		}
	}
	return nil
}

// validatePrefix keeps journal keys to characters that need no escaping in a
// request URL, and rejects the relative segments that would let a prefix walk
// out of itself.
func validatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	for _, seg := range strings.Split(prefix, "/") {
		if seg == "." || seg == ".." {
			return refuseJournal(fmt.Sprintf("prefix segment %q is a relative path", seg), "use a plain prefix such as walden or backups/walden")
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' || c == '_' || c == '.':
			default:
				return refuseJournal(fmt.Sprintf("prefix segment %q contains %q", seg, string(c)), "prefix segments hold only letters, digits, '-', '_', and '.'")
			}
		}
	}
	return nil
}

// validateRegion rejects a region that could not appear in a signing scope.
func validateRegion(region string) error {
	if region == "" {
		return refuseJournal("no region resolved", "add ?region=<region> to WALDEN_JOURNAL or set AWS_REGION")
	}
	for i := 0; i < len(region); i++ {
		c := region[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return refuseJournal(fmt.Sprintf("region %q contains %q", region, string(c)), "regions hold only letters, digits, and '-'")
		}
	}
	return nil
}

// refuseJournal returns a single-line refusal naming the journal knob.
func refuseJournal(why, fix string) error {
	return refusal.RefuseWithCause("invalid journal", why, fix, ErrInvalidJournal)
}

// envValue reads one environment variable through the supplied lookup.
func envValue(lookupEnv func(string) (string, bool), key string) string {
	if lookupEnv == nil {
		return ""
	}
	v, ok := lookupEnv(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// resolveRegion returns the first region named by the sources given, folded to
// lower case. The region is normalised exactly like the host, and for the same
// reason: it appears in endpoint hostnames and in the SigV4 credential scope,
// which is case-sensitive, so "US-EAST-1" would be signed and then rejected.
func resolveRegion(values ...string) string {
	return strings.ToLower(firstNonEmpty(values...))
}

// firstNonEmpty returns the first non-empty string it is given.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
