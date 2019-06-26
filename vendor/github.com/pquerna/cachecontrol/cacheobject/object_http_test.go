/**
 *  Copyright 2015 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package cacheobject

import (
	"github.com/stretchr/testify/require"

	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func roundTrip(t *testing.T, fnc func(w http.ResponseWriter, r *http.Request)) (*http.Request, *http.Response) {
	ts := httptest.NewServer(http.HandlerFunc(fnc))
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	require.NoError(t, err)
	return req, res
}

func TestCachableResponsePublic(t *testing.T) {
	req, res := roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public")
		w.Header().Set("Last-Modified",
			time.Now().UTC().Add(time.Duration(time.Hour*-5)).Format(http.TimeFormat))
		fmt.Fprintln(w, `{}`)
	})

	reasons, expires, err := UsingRequestResponse(req, res.StatusCode, res.Header, false)

	require.NoError(t, err)
	require.Len(t, reasons, 0)
	require.WithinDuration(t,
		time.Now().UTC().Add(time.Duration(float64(time.Hour)*0.5)),
		expires,
		10*time.Second)
}

func TestCachableResponseNoHeaders(t *testing.T) {
	req, res := roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{}`)
	})

	reasons, expires, err := UsingRequestResponse(req, res.StatusCode, res.Header, false)

	require.NoError(t, err)
	require.Len(t, reasons, 0)
	require.True(t, expires.IsZero())
}

func TestCachableResponseBadExpires(t *testing.T) {
	req, res := roundTrip(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Expires", "-1")
		fmt.Fprintln(w, `{}`)
	})

	reasons, expires, err := UsingRequestResponse(req, res.StatusCode, res.Header, false)

	require.NoError(t, err)
	require.Len(t, reasons, 0)
	require.True(t, expires.IsZero())
}
