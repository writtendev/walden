package store

// ProviderHostRow is one row of the provider host table, in the shape a test
// can read. It exists so the external test package can bind the table to the
// published support matrix in internal/journal — store must not import
// journal, so the binding cannot be a compile-time one.
type ProviderHostRow struct {
	Provider string
	Suffix   string
	CAS      bool
}

// ProviderHostsForTest returns the provider host table.
func ProviderHostsForTest() []ProviderHostRow {
	rows := make([]ProviderHostRow, 0, len(providerHosts))
	for _, rule := range providerHosts {
		rows = append(rows, ProviderHostRow{Provider: rule.provider, Suffix: rule.suffix, CAS: rule.cas})
	}
	return rows
}
