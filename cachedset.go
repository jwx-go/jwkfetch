package jwkfetch

import (
	"context"
	"fmt"
	"iter"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// NewCachedSet creates a read-only jwk.Set backed by an httprc resource.
func NewCachedSet(r *httprc.ResourceBase[jwk.Set]) jwk.Set {
	return &cachedSet{r: r}
}

// cachedSet is a read-only jwk.Set backed by a cached resource.
type cachedSet struct {
	r *httprc.ResourceBase[jwk.Set]
}

func (cs *cachedSet) cached() (jwk.Set, error) {
	if err := cs.r.Ready(context.Background()); err != nil {
		return nil, fmt.Errorf(`failed to fetch resource: %w`, err)
	}
	return cs.r.Resource(), nil
}

func (*cachedSet) AddKey(_ jwk.Key) error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}

func (*cachedSet) Clear() error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}

func (*cachedSet) Set(_ string, _ any) error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}

func (*cachedSet) Remove(_ string) error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}

func (*cachedSet) RemoveKey(_ jwk.Key) error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}

func (cs *cachedSet) Clone() (jwk.Set, error) {
	set, err := cs.cached()
	if err != nil {
		return nil, err
	}
	return set.Clone()
}

func (cs *cachedSet) Field(name string) (any, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.Field(name)
}

func (cs *cachedSet) Key(idx int) (jwk.Key, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.Key(idx)
}

func (cs *cachedSet) Index(key jwk.Key) int {
	set, err := cs.cached()
	if err != nil {
		return -1
	}
	return set.Index(key)
}

func (cs *cachedSet) Keys() []string {
	set, err := cs.cached()
	if err != nil {
		return nil
	}
	return set.Keys()
}

func (cs *cachedSet) Len() int {
	set, err := cs.cached()
	if err != nil {
		return -1
	}
	return set.Len()
}

func (cs *cachedSet) LookupKeyID(kid string) (jwk.Key, bool) {
	set, err := cs.cached()
	if err != nil {
		return nil, false
	}
	return set.LookupKeyID(kid)
}

func (cs *cachedSet) All() iter.Seq2[int, jwk.Key] {
	set, err := cs.cached()
	if err != nil {
		return func(func(int, jwk.Key) bool) {}
	}
	return set.All()
}

func (cs *cachedSet) Fields() iter.Seq2[string, any] {
	set, err := cs.cached()
	if err != nil {
		return func(func(string, any) bool) {}
	}
	return set.Fields()
}

func (cs *cachedSet) MarshalJSON() ([]byte, error) {
	set, err := cs.cached()
	if err != nil {
		return nil, err
	}
	return set.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON()
}

func (cs *cachedSet) UnmarshalJSON(data []byte) error {
	return fmt.Errorf(`jwkfetch.CachedSet is immutable`)
}
