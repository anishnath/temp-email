package models

type Issue struct {
	PageReportId int64
	CrawlId      int64
	ErrorType    int
}

type IssueGroup struct {
	ErrorType string `json:"error_type"`
	Priority  int    `json:"priority"`
	Count     int    `json:"count"`
}

type IssueCount struct {
	CriticalIssues []IssueGroup
	AlertIssues    []IssueGroup
	WarningIssues  []IssueGroup
	PassedIssues   []IssueGroup
}
