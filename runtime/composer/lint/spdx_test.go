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
		// D-021: OS packages only under OSI-approved licenses.
		{"MIT-0", SystemOnly, "MIT-0", 0},
		// D-050: free distro licenses that are not OSI-approved, OS packages only.
		{"X11", SystemOnly, "X11", 0},
		{"curl", SystemOnly, "curl", 0},
		{"OpenSSL", SystemOnly, "OpenSSL", 0},
		{"BSD-4-Clause", SystemOnly, "BSD-4-Clause", 0},
		{"IJG", SystemOnly, "IJG", 0},
		{"Libpng", SystemOnly, "Libpng", 0},
		{"libtiff", SystemOnly, "libtiff", 0},
		{"FTL", SystemOnly, "FTL", 0},
		{"bzip2-1.0.6", SystemOnly, "bzip2-1.0.6", 0},
		{"Ruby", SystemOnly, "Ruby", 0},
		{"Vim", SystemOnly, "Vim", 0},
		// D-069: Zend-2.0 (Debian's PHP), OS packages only.
		{"Zend-2.0", SystemOnly, "Zend-2.0", 0},
		{"GFDL-1.3-or-later", SystemOnly, "GFDL-1.3-or-later", 0},
		{"GFDL-1.2-no-invariants-only", SystemOnly, "GFDL-1.2-no-invariants-only", 0},
		{"GFDL-2.0", Unknown, "GFDL-2.0", 0},
		{"FTL OR GPL-2.0-or-later", Allowed, "GPL-2.0-or-later", 0},
		{"CC-BY-NC-4.0", Unknown, "CC-BY-NC-4.0", 0},
		// D-050: OSI-approved permissive additions.
		{"BlueOak-1.0.0", Allowed, "BlueOak-1.0.0", 0},
		{"ZPL-2.1", Allowed, "ZPL-2.1", 0},
		{"CNRI-Python", Allowed, "CNRI-Python", 0},
		{"CNRI-Python AND PSF-2.0", Allowed, "CNRI-Python AND PSF-2.0", 0},
		// D-050: CC-BY-4.0 for data-only packages.
		{"CC-BY-4.0", DataOnly, "CC-BY-4.0", 0},
		{"MIT AND CC-BY-4.0", DataOnly, "MIT AND CC-BY-4.0", 0},
		{"CC-BY-4.0 OR MIT", Allowed, "MIT", 0},
		{"CC-BY-SA-4.0", Unknown, "CC-BY-SA-4.0", 0},
	}
	for _, c := range cases {
		r := EvaluateLicense(c.expr)
		if r.Status != c.status || (c.elected != "" && r.Elected != c.elected) || len(r.Banned) != c.banned {
			t.Errorf("%q: got %s elected %q banned %v, want %s %q %d", c.expr, r.Status, r.Elected, r.Banned, c.status, c.elected, c.banned)
		}
	}
}
