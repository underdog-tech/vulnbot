package querying

import "sync"

// A DataSource represents an single source (service) for discovering projects
// and their associated findings.
//
// CollectFindings must add all discovered projects and findings to the shared
// [ProjectCollection] object, using the [ProjectCollection.GetProject] and
// [Project.GetFinding] methods. These handle all necessary locking and merging
// of data between data sources, as they will all be processing their data
// simultaneously.
//
// Upon completion of collection, CollectFindings must call `Done()` on the
// [sync.WaitGroup], to indicate it is done.
type DataSource interface {
	CollectFindings(
		*ProjectCollection,
		*sync.WaitGroup,
	) error
}
