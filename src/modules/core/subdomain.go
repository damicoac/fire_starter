package core



// getDefaultWordlist returns a common subdomain wordlist for brute-force enumeration
func getDefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "api", "admin", "dev", "staging",
		"test", "prod", "stage", "qa", "sandbox", "demo",
		"app", "web", "smtp", "pop3", "imap", "dns",
		"ns1", "ns2", "mx", "ns", "cdn", "static",
		"assets", "media", "img", "images", "files",
		"blog", "shop", "store", "docs", "help",
		"support", "portal", "dashboard", "login", "auth",
		"api-v1", "api-v2", "v1", "v2", "graphql",
		"git", "svn", "hg", "cvs", "ci", "cd",
		"jenkins", "travis", "circleci", "github",
		"status", "health", "metrics", "monitoring",
		"prometheus", "grafana", "elk", "kibana",
		"elastic", "logs", "logging",
		"internal", "private", "secure", "vault",
		"keyserver", "ldap", "radius", "acs",
		"sso", "oauth", "oidc",
		"auth0", "okta", "azuread", "identity",
		"cdn1", "cdn2", "edge", "origin",
		"backup", "archive", "old", "legacy",
		"deprecated", "temp",
		"mobile", "ios", "android", "webapp",
		"m", "m2", "mobile-api", "api-mobile",
		"dev1", "dev2", "staging1", "staging2",
		"uat", "preprod", "production", "prod1", "prod2",
		"db", "database", "mysql", "postgres", "mongo",
		"redis", "memcached", "cache", "elasticsearch",
		"search", "index", "crawler", "bot",
		"webmail", "cpanel", "whm",
		"ftp1", "ftp2", "ftptest", "sftp-test",
		"smtp-relay", "mail-relay", "mx1", "mx2",
		"webdav", "dav",
		"zookeeper", "kafka", "rabbitmq",
		"jira", "confluence", "wiki", "redmine",
		"gitlab", "gerrit",
		"cloudfront", "aws", "azure",
		"gcp", "office365", "sharepoint",
		"teams", "zendesk", "salesforce", "hubspot",
	}
}
