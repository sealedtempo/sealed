package lint

import "testing"

func TestEvaluateLicense(t *testing.T) {
	cases := []struct {
		expr    string
		status  LicenseStatus
		elected string
		banned  int
	}{
		{"MIT", Allowed, "MIT", 0},
		{"Apache-2.0", Allowed, "Apache-2.0", 0},
		{"AGPL-3.0", Allowed, "AGPL-3.0-only", 0},
		{"AGPL-3.0-only", Allowed, "AGPL-3.0-only", 0},
		{"GPL-2.0+", Allowed, "GPL-2.0-or-later", 0},
		{"GPL-2.0-only", SystemOnly, "GPL-2.0-only", 0},
		{"GPL-2.0", SystemOnly, "GPL-2.0-only", 0},
		{"LGPL-2.1-or-later", Allowed, "LGPL-2.1-or-later", 0},
		{"PostgreSQL", Allowed, "PostgreSQL", 0},
		{"BSL-1.0", Allowed, "BSL-1.0", 0},
		{"BUSL-1.1", Banned, "BUSL-1.1", 1},
		{"SSPL-1.0", Banned, "SSPL-1.0", 1},
		{"Elastic-2.0", Banned, "Elastic-2.0", 1},
		{"FSL-1.1-MIT", Banned, "FSL-1.1-MIT", 1},
		{"LicenseRef-Proprietary", Banned, "LicenseRef-Proprietary", 1},
		{"LicenseRef-Sustainable-Use-License", Banned, "LicenseRef-Sustainable-Use-License", 1},
		{"Apache-2.0 WITH Commons-Clause", Banned, "Apache-2.0 WITH Commons-Clause", 1},
		{"Apache-2.0 WITH LLVM-exception", Allowed, "Apache-2.0 WITH LLVM-exception", 0},
		{"GPL-2.0-only WITH Classpath-exception-2.0", SystemOnly, "GPL-2.0-only WITH Classpath-exception-2.0", 0},
		// Redis 8: tri-license, used under AGPLv3.
		{"LicenseRef-RSALv2 OR SSPL-1.0 OR AGPL-3.0-only", Allowed, "AGPL-3.0-only", 2},
		{"LicenseRef-RSALv2", Banned, "LicenseRef-RSALv2", 1},
		{"MIT AND Apache-2.0", Allowed, "MIT AND Apache-2.0", 0},
		{"MIT AND BUSL-1.1", Banned, "MIT AND BUSL-1.1", 1},
		{"(MIT OR BUSL-1.1) AND Apache-2.0", Allowed, "MIT AND Apache-2.0", 1},
		{"mit or apache-2.0", Unknown, "mit", 0}, // ids are case-sensitive; operators are not
		{"MIT or Apache-2.0", Allowed, "MIT", 0},
		{"MIT OR GPL-2.0-only", Allowed, "MIT", 0},
		{"GPL-2.0-only OR LicenseRef-Foo", SystemOnly, "GPL-2.0-only", 0},
		{"Apache-2.0+", Allowed, "Apache-2.0", 0},
		{"WTFPL", Unknown, "WTFPL", 0},
		{"", Unknown, "", 0},
		{"MIT AND", Unknown, "", 0},
		{"(MIT", Unknown, "", 0},
		{"MIT)", Unknown, "", 0},
		{"MIT WITH", Unknown, "", 0},
		{"(MIT OR ISC) WITH X", Unknown, "", 0},
		{"NOASSERTION", Unknown, "NOASSERTION", 0},
		{"MIT;rm", Unknown, "", 0},
	}
	for _, c := range cases {
		r := EvaluateLicense(c.expr)
		if r.Status != c.status || (c.elected != "" && r.Elected != c.elected) || len(r.Banned) != c.banned {
			t.Errorf("%q: got %s elected %q banned %v, want %s %q %d", c.expr, r.Status, r.Elected, r.Banned, c.status, c.elected, c.banned)
		}
	}
}
