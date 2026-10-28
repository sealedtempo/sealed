// Package schema embeds the catalog manifest JSON Schema so Go tools validate
// against exactly the file in this directory.
package schema

import _ "embed"

// ManifestURL is the schema's $id.
const ManifestURL = "https://sealed.dev/schema/manifest.schema.json"

// ManifestJSON is catalog/schema/manifest.schema.json.
//
//go:embed manifest.schema.json
var ManifestJSON []byte
