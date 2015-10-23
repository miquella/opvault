package opvault

import (
	"encoding/base64"
)

type dataMap map[string]interface{}

func (d dataMap) getBool(key string) bool {
	val, _ := d[key].(bool)
	return val
}

func (d dataMap) getInt(key string) int {
	val, _ := d[key].(float64)
	return int(val)
}

func (d dataMap) getInt64(key string) int64 {
	val, _ := d[key].(float64)
	return int64(val)
}

func (d dataMap) getString(key string) string {
	val, _ := d[key].(string)
	return val
}

func (d dataMap) getStringSlice(key string) []string {
	val, _ := d[key].([]interface{})
	if len(val) == 0 {
		return []string{}
	}

	strs := []string{}
	for _, i := range val {
		if s, ok := i.(string); ok {
			strs = append(strs, s)
		}
	}

	return strs
}

func (d dataMap) getMapSlice(key string) []map[string]interface{} {
	val, _ := d[key].([]interface{})
	if len(val) == 0 {
		return []map[string]interface{}{}
	}

	maps := []map[string]interface{}{}
	for _, m := range val {
		if m, ok := m.(map[string]interface{}); ok {
			maps = append(maps, m)
		}
	}

	return maps
}

func (d dataMap) getBytes(key string) []byte {
	val, _ := d[key].(string)
	if val == "" {
		return nil
	}

	data, _ := base64.StdEncoding.DecodeString(val)
	return data
}
