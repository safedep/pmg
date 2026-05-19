package doctor

type CheckStatus int

const (
	StatusPass CheckStatus = iota
	StatusWarn
	StatusFail
)

type CheckResult struct {
	Name     string
	Category string
	Status   CheckStatus
	Message  string
}

type Check struct {
	Name     string
	Category string
	Run      func() CheckResult
}

func RunChecks(checks []Check) []CheckResult {
	results := make([]CheckResult, 0, len(checks))
	for _, c := range checks {
		result := c.Run()
		result.Name = c.Name
		result.Category = c.Category
		results = append(results, result)
	}
	return results
}

func HasFailures(results []CheckResult) bool {
	for _, r := range results {
		if r.Status == StatusFail {
			return true
		}
	}
	return false
}

func CategorySummary(results []CheckResult) map[string]CheckStatus {
	summary := make(map[string]CheckStatus)
	for _, r := range results {
		current, exists := summary[r.Category]
		if !exists || r.Status > current {
			summary[r.Category] = r.Status
		}
	}
	return summary
}
