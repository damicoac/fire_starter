package agent

// Session matrix: every technique tool call can run against multiple session
// variants. Unauthenticated execution is always attempted; when the knowledge
// graph holds cookies or credentials for a target and the module is
// session-aware, an authenticated "default" session run is added. Callers may
// also pin a single session with a "session_id" tool argument.

// selectSessions determines which session variants a tool call runs against:
// the explicitly requested session when "session_id" is set, otherwise the
// unauthenticated run plus the authenticated default run when the target has
// an auth context and the module is session-aware.
func selectSessions(env *agentEnv, toolName string, args map[string]any, targetUsed string) []string {
	sessionID, hasSession := args["session_id"].(string)
	if hasSession && sessionID != "" {
		return []string{sessionID}
	}

	hasAuthContext := env.kg.GetCookiesForRequest("default", targetUsed) != "" || len(env.kg.GetCredentials()) > 0
	if hasAuthContext && env.executor.IsSessionAware(toolName) {
		return []string{"unauthenticated", "default"}
	}
	return []string{"unauthenticated"}
}

// applySessionContext injects the harvested cookies and the first stored
// credential into a session-variant payload. Unauthenticated runs get an
// explicitly empty cookie header so no ambient state leaks in.
func applySessionContext(env *agentEnv, iterPayload map[string]any, sess string, targetUsed string) {
	if sess == "unauthenticated" {
		iterPayload["cookies"] = ""
		return
	}

	if cookiesStr := env.kg.GetCookiesForRequest(sess, targetUsed); cookiesStr != "" {
		iterPayload["cookies"] = cookiesStr
	}
	if _, hasUsername := iterPayload["username"]; !hasUsername {
		credentials := env.kg.GetCredentials() // Still using global credentials array for backward compatibility
		if len(credentials) > 0 {
			iterPayload["username"] = credentials[0].Username
			iterPayload["password"] = credentials[0].Password
		}
	}
}
