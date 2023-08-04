package querying

import "sync"

type DataSource interface {
	CollectFindings(
		*ProjectCollection,
		*sync.WaitGroup,
	) error
}
