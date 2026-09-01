package store

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
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
	// Everything below may quote a value read out of the URL. This is the one
	// gate that makes that safe; see guardCredentials.
	if err := guardCredentials(raw, u); err != nil {
		return nil, err
	}
	if u.Fragment != "" {
		return nil, refuseJournal("URL carries a fragment", "remove everything from the '#' onwards")
	}

	scheme := strings.ToLower(u.Scheme)
	switch {
	case supportedScheme(scheme):
	case scheme == "":
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
		// to a bucket named "minio.local" at Amazon. The test is the ':'
		// rather than u.Port(), which is empty for both "s3://bucket:" and
		// a port net/url could not read.
		if strings.Contains(u.Host, ":") {
			return nil, refuseJournal(
				"s3:// URL carries a port, but s3:// always addresses AWS",
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
		bucketLabel, endpointHost, isEndpoint := "", host, true
		if known {
			bucketLabel, endpointHost, isEndpoint = rule.split(host)
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
		if !isEndpoint {
			// A provider host with no "s3" label anywhere in it is not an
			// endpoint. Read as one, https://amazonaws.com/bucket/walden
			// resolved to a region named "com".
			return nil, refuseJournal(
				fmt.Sprintf("host %q names no S3 endpoint", host),
				fmt.Sprintf("expected an endpoint such as s3.<region>.%s", rule.suffix))
		}

		switch style {
		case "path":
			j.PathStyle = true
		case "virtual":
			j.PathStyle = false
		default:
			j.PathStyle = bucketLabel == ""
		}

		// Where the bucket is written and how the request addresses it are
		// separate questions. A bucket label in the hostname names the
		// bucket under either style, so an operator may also state
		// outright the path-style walden would have chosen anyway.
		if bucketLabel != "" {
			j.Bucket = bucketLabel
			j.Prefix = strings.Join(segments, "/")
		} else {
			if len(segments) == 0 {
				return nil, refuseJournal("URL names no bucket", "expected https://endpoint/bucket/prefix")
			}
			j.Bucket = segments[0]
			j.Prefix = strings.Join(segments[1:], "/")
		}

		hostRegion, hostNamesRegion := rule.regionFromHost(endpointHost)
		if !hostNamesRegion && region == "" {
			return nil, refuseJournal(
				fmt.Sprintf("endpoint host %q fronts every region and names none", endpointHost),
				"add ?region=<region> to WALDEN_JOURNAL")
		}

		j.Endpoint = scheme + "://" + hostPort(endpointHost, u.Port())
		j.Region = resolveRegion(
			region,
			hostRegion,
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

// guardCredentials is the one gate that makes every other refusal in this file
// safe to quote a URL-derived value.
//
// A journal URL may carry an object-storage secret, and net/url is only half a
// defence. When it returns an error the secret is still lexically in the
// userinfo and walden refuses without echoing. But an unencoded '/', '?', or
// '#' inside the credentials ends the authority before the '@', and then
// net/url returns no error at all: it silently relocates the tail of the secret
// into the host, the port, the path, or the query — fields the refusals below
// treat as safe to print.
//
// The invariant that separates the two cases is the '@'. It ends the
// credentials in the authority and has no other place in a journal URL: not in
// a host, a bucket, a prefix, a region, or a style, all of which already refuse
// it. So an '@' surviving outside the userinfo means net/url has read the URL
// differently from the operator who wrote it, and the bytes in front of that
// '@' are the secret. Refuse there, once, without echoing anything.
//
// Past this gate the credentials are confined to u.User, which no refusal
// prints, and every other field of the URL is free of them.
func guardCredentials(raw string, u *url.URL) error {
	tail := raw[credentialsEnd(raw):]
	if strings.Contains(tail, "@") {
		return refuseRelocatedCredentials()
	}
	// Percent-encoded, an '@' reaches a refusal only after net/url decodes
	// it back — into a host or a path segment walden would quote.
	if decoded, err := url.PathUnescape(tail); err == nil && strings.Contains(decoded, "@") {
		return refuseRelocatedCredentials()
	}
	// The scheme is the other place a credential can land: net/url reads
	// ACCESS_KEY://SECRET@host as scheme "ACCESS_KEY". A URL that carries
	// credentials under a scheme walden does not serve is refused without
	// the scheme being named.
	if u.User != nil && !supportedScheme(u.Scheme) {
		return refuseJournal(
			"URL scheme is unsupported; it is not echoed because it may be part of the credentials",
			"expected s3://, https://, or http://")
	}
	return nil
}

// supportedScheme reports whether walden serves a journal under this scheme.
func supportedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "s3", "https", "http":
		return true
	}
	return false
}

// refuseRelocatedCredentials refuses without naming any part of the URL.
func refuseRelocatedCredentials() error {
	return refuseJournal(
		"URL is malformed; it is not echoed because it may carry credentials",
		"percent-encode reserved characters in the credentials, as in s3://ACCESS_KEY:SEC%2FRET@bucket/prefix")
}

// credentialsEnd returns the number of leading bytes of raw that hold the
// scheme, the "//", and the userinfo through the '@' that ends it — the only
// part of a journal URL that may hold credentials. It is 0 when there is no
// userinfo. The authority is delimited exactly as net/url delimits it: the
// fragment, then the query, then the first '/' after the "//".
func credentialsEnd(raw string) int {
	rest := raw
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	start := 0
	if i := strings.Index(rest, "://"); i >= 0 && isScheme(rest[:i]) {
		start = i + len("://")
	} else if strings.HasPrefix(rest, "//") {
		start = len("//")
	} else {
		return 0
	}
	authority := rest[start:]
	if i := strings.Index(authority, "/"); i >= 0 {
		authority = authority[:i]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return 0
	}
	return start + at + 1
}

// isScheme reports whether s is a URL scheme, by the same rule net/url applies.
func isScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9', c == '+', c == '-', c == '.':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// journalQuery reads the two query parameters walden accepts and refuses any
// other. The query is case-insensitive throughout — the region has to be folded
// anyway, since it is case-sensitive in the SigV4 credential scope, and a rule
// that folds the values but not the keys is a rule nobody can remember. A
// parameter given twice is refused rather than silently resolved to one of
// them; the keys are read in sorted order so which one a refusal names does not
// depend on map iteration.
func journalQuery(u *url.URL) (region, style string, err error) {
	q, parseErr := url.ParseQuery(u.RawQuery)
	if parseErr != nil {
		// Same reason as the URL itself: the parse error quotes the input
		// back, and no part of a journal URL is echoed.
		return "", "", refuseJournal("query string is malformed", "the only query parameters are region and style")
	}
	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make(map[string]string, len(keys))
	for _, key := range keys {
		canonical := strings.ToLower(key)
		switch canonical {
		case "region", "style":
		default:
			return "", "", refuseJournal(fmt.Sprintf("unknown query parameter %q", key), "the only query parameters are region and style")
		}
		if _, repeated := values[canonical]; repeated || len(q[key]) > 1 {
			return "", "", refuseJournal(fmt.Sprintf("query parameter %q is given more than once", canonical), "give region and style at most once each")
		}
		values[canonical] = q[key][0]
	}

	region = strings.TrimSpace(values["region"])
	style = strings.TrimSpace(strings.ToLower(values["style"]))
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
// means the URL is path-style. isEndpoint is false when an AWS-style host
// carries no "s3" label at all, which makes it no endpoint of this provider.
func (r providerHost) split(host string) (bucket, endpoint string, isEndpoint bool) {
	labels := strings.Split(host, ".")
	if r.endpointLabels < 0 {
		// Scan from the right so a bucket named "s3-backups" is not
		// mistaken for the start of the endpoint host.
		for i := len(labels) - 1; i >= 0; i-- {
			if labels[i] == "s3" || strings.HasPrefix(labels[i], "s3-") {
				return strings.Join(labels[:i], "."), strings.Join(labels[i:], "."), true
			}
		}
		return "", host, false
	}
	if len(labels) <= r.endpointLabels {
		return "", host, true
	}
	n := len(labels) - r.endpointLabels
	return strings.Join(labels[:n], "."), strings.Join(labels[n:], "."), true
}

// awsEndpointModifiers are the labels AWS writes where a region label could
// otherwise stand. They are not regions. FIPS and dualstack qualify a regional
// endpoint and leave the region elsewhere in the host; accelerate replaces it,
// because one accelerate endpoint fronts every region at once.
var awsEndpointModifiers = map[string]bool{
	"dualstack":  true,
	"fips":       true,
	"accelerate": true,
}

// regionFromHost returns the region named in a bare endpoint host. It reads the
// AWS-style layouts s3.<region>, s3-<region>, s3.dualstack.<region>, and
// s3-fips.<region>, which Backblaze B2 and Wasabi share, plus the bare "s3"
// global endpoint, which names no region and defaults to us-east-1.
//
// namesRegion is false only for a host whose region label is a modifier that
// replaces it — s3-accelerate. There is no region to read there and no sane
// default, so the caller refuses rather than sign a scope AWS will reject. The
// old rule read the label after "s3-" as the region unconditionally, which made
// s3-fips.us-east-1.amazonaws.com resolve to region "fips".
func (r providerHost) regionFromHost(endpoint string) (region string, namesRegion bool) {
	if r.endpointLabels >= 0 {
		return "", true
	}
	labels := strings.Split(strings.TrimSuffix(endpoint, "."+r.suffix), ".")
	if len(labels) == 0 || labels[0] == "" {
		return "", true
	}
	// A region label to the right of the "s3" label wins: in
	// s3-fips.us-east-1 the modifier is the qualifier, not the region.
	for _, label := range labels[1:] {
		if label != "" && !awsEndpointModifiers[label] {
			return label, true
		}
	}
	tail, legacy := strings.CutPrefix(labels[0], "s3-")
	switch {
	case !legacy || tail == "":
		// The bare "s3" global endpoint. It has a default region.
		return "", true
	case awsEndpointModifiers[tail]:
		return "", false
	default:
		return tail, true
	}
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
