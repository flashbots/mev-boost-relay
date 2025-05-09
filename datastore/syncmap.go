package datastore

import "sync"

type syncMap[K comparable, V any] struct {
	m sync.Map
}

func (m *syncMap[K, V]) Load(key K) (V, bool) { //nolint:ireturn
	var vZero V

	v, ok := m.m.Load(key)
	if !ok {
		return vZero, false
	}

	vv, ok := v.(V)
	if !ok {
		// should be unreachable
		return vZero, false
	}

	return vv, true
}

func (m *syncMap[K, V]) LoadOrStore(key K, value V) (actual any, loaded bool) {
	return m.m.LoadOrStore(key, value)
}

func (m *syncMap[K, V]) Store(key K, value V) {
	m.m.Store(key, value)
}
