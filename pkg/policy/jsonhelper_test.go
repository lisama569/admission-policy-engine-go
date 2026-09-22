package policy

import "encoding/json"

func unmarshalLoose(raw []byte, v any) error {
	return json.Unmarshal(raw, v)
}
