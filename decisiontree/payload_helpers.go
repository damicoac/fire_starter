package decisiontree

import "fmt"

func requireString(payload map[string]any, key string) (string, error) {
	value, ok := payload[key]
	if !ok {
		return "", fmt.Errorf("missing payload key %q", key)
	}
	stringValue, ok := value.(string)
	if !ok || stringValue == "" {
		return "", fmt.Errorf("payload key %q must be a non-empty string", key)
	}
	return stringValue, nil
}

func getBool(payload map[string]any, key string) bool {
	value, ok := payload[key]
	if !ok {
		return false
	}
	boolValue, ok := value.(bool)
	if !ok {
		return false
	}
	return boolValue
}

func copyPayload(payload map[string]any) map[string]any {
	cloned := make(map[string]any, len(payload))
	for key, value := range payload {
		cloned[key] = value
	}
	return cloned
}
