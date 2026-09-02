package store

// ProviderHostRow is one row of the provider host table, in the shape a test
// can read. The table and its fields are unexported, so the external test
// package reaches them through this row rather than directly. There is no Go
// table anywhere else to bind it to: spec/journal/v1 section 11.2 is
// documentation, and compare-and-swap is the boot probe's business.
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
