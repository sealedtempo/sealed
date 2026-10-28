package lint

// acceptedExceptionDecisions lists the decision ids under which a manifest's
// license_exceptions are honoured (integration brief item 17). A manifest
// entry naming any other decision is a lint error, and its paths stay
// subject to every license and excluded-path check.
//
// It is empty: no decision grants an exception. D-019 (Twenty's enterprise
// files in the official image) was withdrawn by D-049, so crm gets none.
// Adding an id here needs a recorded decision in docs/DECISIONS.md that
// names the app, the paths and why shipping them is allowed.
var acceptedExceptionDecisions = map[string]bool{}

// AcceptedExceptionDecisions returns the decision ids lint accepts, sorted.
func AcceptedExceptionDecisions() []string { return sortedKeys(acceptedExceptionDecisions) }
