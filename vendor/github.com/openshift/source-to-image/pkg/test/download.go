package test

import (
	"net/url"
	"sync"

	"github.com/openshift/source-to-image/pkg/scm/git"
)

// FakeDownloader provides a fake downloader interface
type FakeDownloader struct {
	URL    []url.URL
	Target []string
	Err    map[string]error
	mutex  sync.Mutex
}

// Download downloads a fake file from the URL
func (f *FakeDownloader) Download(url *url.URL, target string) (*git.SourceInfo, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.URL = append(f.URL, *url)
	f.Target = append(f.Target, target)

	return &git.SourceInfo{Location: target, CommitID: "1bf4f04"}, f.Err[url.String()]
}
