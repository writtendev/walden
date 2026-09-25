package githttp

import "testing"

// TestGitEnvPinsSystemAndGlobalConfig is the fast, portable regression gate
// for WALD-127: gitEnv must hand every git child GIT_CONFIG_GLOBAL and
// GIT_CONFIG_SYSTEM pinned to /dev/null, the same spelling
// internal/store/repo.go already uses on its own git children, so a
// core.hooksPath or uploadpack.packObjectsHook set in /etc/gitconfig or the
// server user's ~/.gitconfig cannot reach any route this package serves.
//
// This test only reads gitEnv's return value; it proves the string, not the
// behavior. cmd/walden/gitconfig_unix_test.go is the end-to-end proof that a
// hostile system config is actually defeated.
func TestGitEnvPinsSystemAndGlobalConfig(t *testing.T) {
	for _, wantV2 := range []bool{false, true} {
		env := gitEnv(wantV2)

		want := map[string]bool{
			"GIT_CONFIG_GLOBAL=/dev/null": false,
			"GIT_CONFIG_SYSTEM=/dev/null": false,
		}
		for _, kv := range env {
			if _, ok := want[kv]; ok {
				want[kv] = true
			}
		}
		for kv, found := range want {
			if !found {
				t.Errorf("gitEnv(%v) = %v, missing %q", wantV2, env, kv)
			}
		}
	}
}
