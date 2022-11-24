// DNS Rewrites

package filtering

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rewrite"
	"github.com/AdguardTeam/golibs/log"
)

// prepareRewrites normalizes and validates all DNS rewrites.
func (d *DNSFilter) prepareRewrites() (err error) {
	for i, r := range d.Rewrites {
		err = r.Normalize()
		if err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}
	}

	d.rewriteStorage, err = rewrite.NewDefaultStorage(RewritesListID, d.Rewrites)
	if err != nil {
		return fmt.Errorf("init storage: %s", err)
	}

	return nil
}

type rewriteEntryJSON struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

func (d *DNSFilter) handleRewriteList(w http.ResponseWriter, r *http.Request) {
	arr := []*rewriteEntryJSON{}

	d.confLock.Lock()
	for _, ent := range d.rewriteStorage.List() {
		jsent := rewriteEntryJSON{
			Domain: ent.Domain,
			Answer: ent.Answer,
		}
		arr = append(arr, &jsent)
	}
	d.confLock.Unlock()

	_ = aghhttp.WriteJSONResponse(w, r, arr)
}

func (d *DNSFilter) handleRewriteAdd(w http.ResponseWriter, r *http.Request) {
	rwJSON := rewriteEntryJSON{}
	err := json.NewDecoder(r.Body).Decode(&rwJSON)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json.Decode: %s", err)

		return
	}

	rw := &rewrite.Item{
		Domain: rwJSON.Domain,
		Answer: rwJSON.Answer,
	}

	err = rw.Normalize()
	if err != nil {
		// Shouldn't happen currently, since normalize only returns a non-nil
		// error when a rewrite is nil, but be change-proof.
		aghhttp.Error(r, w, http.StatusBadRequest, "normalizing: %s", err)

		return
	}

	d.confLock.Lock()
	defer d.confLock.Unlock()

	err = d.rewriteStorage.Add(rw)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "add rewrite item: %s", err)

		return
	}

	log.Debug("rewrite: added element: %s -> %s [%d]", rw.Domain, rw.Answer, len(d.Config.Rewrites))

	d.Config.ConfigModified()
}

func (d *DNSFilter) handleRewriteDelete(w http.ResponseWriter, r *http.Request) {
	jsent := rewriteEntryJSON{}
	err := json.NewDecoder(r.Body).Decode(&jsent)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json.Decode: %s", err)

		return
	}

	ent := &rewrite.Item{
		Domain: jsent.Domain,
		Answer: jsent.Answer,
	}

	d.confLock.Lock()
	defer d.confLock.Unlock()

	err = d.rewriteStorage.Remove(ent)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "remove rewrite item: %s", err)

		return
	}

	log.Debug("rewrite: removed element: %s -> %s", ent.Domain, ent.Answer)

	d.Config.ConfigModified()
}
