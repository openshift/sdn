/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fieldpath

import (
	"testing"

	"sigs.k8s.io/structured-merge-diff/value"
)

func TestFromValue(t *testing.T) {
	table := []struct {
		objYAML string
		set     *Set
	}{
		{`a: a`, NewSet(MakePathOrDie("a"))},
		{`{"a": [{"a": null}]}`, NewSet(
			MakePathOrDie("a", 0, "a"),
		)}, {`{"a": [{"id": a}]}`, NewSet(
			MakePathOrDie("a", KeyByFields("id", value.StringValue("a")), "id"),
		)}, {`{"a": [{"name": a}]}`, NewSet(
			MakePathOrDie("a", KeyByFields("name", value.StringValue("a")), "name"),
		)}, {`{"a": [{"key": a}]}`, NewSet(
			MakePathOrDie("a", KeyByFields("key", value.StringValue("a")), "key"),
		)}, {`{"a": [{"name": "a", "key": "b"}]}`, NewSet(
			MakePathOrDie("a", KeyByFields(
				"name", value.StringValue("a"),
				"key", value.StringValue("b"),
			), "key"),
			MakePathOrDie("a", KeyByFields(
				"name", value.StringValue("a"),
				"key", value.StringValue("b"),
			), "name"),
		)}, {`{"a": [5]}`, NewSet(
			MakePathOrDie("a", 0),
		)}, {`{"a": [5,4,3]}`, NewSet(
			MakePathOrDie("a", 0),
			MakePathOrDie("a", 1),
			MakePathOrDie("a", 2),
		)}, {`{"a": [[5]]}`, NewSet(
			MakePathOrDie("a", 0, 0),
		)}, {`{"a": 1, "b": true, "c": 1.5, "d": null}`, NewSet(
			MakePathOrDie("a"),
			MakePathOrDie("b"),
			MakePathOrDie("c"),
			MakePathOrDie("d"),
		)},
	}

	for _, tt := range table {
		tt := tt
		t.Run(tt.objYAML, func(t *testing.T) {
			t.Parallel()
			v, err := value.FromYAML([]byte(tt.objYAML))
			if err != nil {
				t.Fatalf("couldn't parse: %v", err)
			}
			got := SetFromValue(v)
			if !got.Equals(tt.set) {
				t.Errorf("wanted\n%s\nbut got\n%s\n", tt.set, got)
			}
		})
	}
}
