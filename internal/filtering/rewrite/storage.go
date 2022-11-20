// Package rewrite implements DNS Rewrites storage and request matching.
package rewrite

import (
	"fmt"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
)

// Storage is a storage for rewrite rules.
type Storage interface {
	// Match finds a matching rule for the specified hostname.
	Match(hostname string) (res *urlfilter.DNSResult, matched bool)

	// AddRule creates rule from text and adds it to the storage.
	AddRule(line string) (err error)

	// ReadRules returns all rules from the storage.
	ReadRules() (lines []string)

	// RemoveRule deletes rule from the storage.
	RemoveRule(line string) (err error)
}

// DefaultStorage is the default storage for rewrite rules.
type DefaultStorage struct {
	// mu protects items.
	mu *sync.RWMutex

	// engine is the DNS filtering engine.
	engine *urlfilter.DNSEngine

	// ruleList is the filtering rule ruleList used by the engine.
	ruleList filterlist.RuleList

	// urlFilterID is the synthetic integer identifier for the urlfilter engine.
	//
	// TODO(a.garipov): Change the type to a string in module urlfilter and
	// remove this crutch.
	urlFilterID int

	// rulesText is an array of rule lines.
	rulesText []string
}

// DefaultStorageConfig contains configuration for a rewrite storage.
type DefaultStorageConfig struct {
	// rulesText is an array of rule lines.
	rulesText []string
}

// NewDefaultStorage returns new rewrites storage.  listID is used as an
// identifier of the underlying rules list.  c must not be nil.
func NewDefaultStorage(listID int, c *DefaultStorageConfig) (s *DefaultStorage, err error) {
	s = &DefaultStorage{
		mu:          &sync.RWMutex{},
		urlFilterID: listID,
		rulesText:   c.rulesText,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	err = s.resetRules()
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Config returns storage configuration.
func (s *DefaultStorage) Config() (c *DefaultStorageConfig) {
	return &DefaultStorageConfig{
		rulesText: s.rulesText,
	}
}

// type check
var _ Storage = (*DefaultStorage)(nil)

// Match implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) Match(hostname string) (res *urlfilter.DNSResult, matched bool) {
	return s.engine.Match(hostname)
}

// AddRule implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) AddRule(line string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rulesText = append(s.rulesText, line)

	return s.resetRules()
}

// ReadRules implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) ReadRules() (lines []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.rulesText
}

// RemoveRule implements the Storage interface for *DefaultStorage.
func (s *DefaultStorage) RemoveRule(line string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var filtered []string
	for i, r := range s.rulesText {
		if r != line {
			filtered = append(filtered, s.rulesText[i])
		}
	}

	s.rulesText = filtered

	return s.resetRules()
}

// resetRules resets the filtering rules.
func (s *DefaultStorage) resetRules() (err error) {
	strList := &filterlist.StringRuleList{
		ID:             s.urlFilterID,
		RulesText:      strings.Join(s.rulesText, "\n"),
		IgnoreCosmetic: true,
	}

	rs, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
	if err != nil {
		return fmt.Errorf("creating list storage: %w", err)
	}

	s.ruleList = strList
	s.engine = urlfilter.NewDNSEngine(rs)

	log.Info("filter %d: reset %d rules", s.urlFilterID, s.engine.RulesCount)

	return nil
}
