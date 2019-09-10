/*
Copyright 2019 The Kubernetes Authors.

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

package merge_test

import (
	"testing"

	"sigs.k8s.io/structured-merge-diff/fieldpath"
	. "sigs.k8s.io/structured-merge-diff/internal/fixture"
	"sigs.k8s.io/structured-merge-diff/merge"
	"sigs.k8s.io/structured-merge-diff/typed"
)

var unionFieldsParser = func() typed.ParseableType {
	parser, err := typed.NewParser(`types:
- name: unionFields
  map:
    fields:
    - name: numeric
      type:
        scalar: numeric
    - name: string
      type:
        scalar: string
    - name: type
      type:
        scalar: string
    - name: fieldA
      type:
        scalar: string
    - name: fieldB
      type:
        scalar: string
    unions:
    - discriminator: type
      deduceInvalidDiscriminator: true
      fields:
      - fieldName: numeric
        discriminatorValue: Numeric
      - fieldName: string
        discriminatorValue: String
    - fields:
      - fieldName: fieldA
        discriminatorValue: FieldA
      - fieldName: fieldB
        discriminatorValue: FieldB`)
	if err != nil {
		panic(err)
	}
	return parser.Type("unionFields")
}()

func TestUnion(t *testing.T) {
	tests := map[string]TestCase{
		"union_apply_owns_discriminator": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						numeric: 1
					`,
				},
			},
			Object: `
				numeric: 1
				type: Numeric
			`,
			Managed: fieldpath.ManagedFields{
				"default": &fieldpath.VersionedSet{
					Set: _NS(
						_P("numeric"), _P("type"),
					),
					APIVersion: "v1",
				},
			},
		},
		"union_apply_without_discriminator_conflict": {
			Ops: []Operation{
				Update{
					Manager:    "controller",
					APIVersion: "v1",
					Object: `
						string: "some string"
					`,
				},
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						numeric: 1
					`,
					Conflicts: merge.Conflicts{
						merge.Conflict{Manager: "controller", Path: _P("type")},
					},
				},
			},
			Object: `
				string: "some string"
				type: String
			`,
			Managed: fieldpath.ManagedFields{
				"controller": &fieldpath.VersionedSet{
					Set: _NS(
						_P("string"), _P("type"),
					),
					APIVersion: "v1",
				},
			},
		},
		"union_apply_with_null_value": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						type: Numeric
						string: null
						numeric: 1
					`,
				},
			},
		},
		"union_apply_multiple_unions": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						string: "some string"
						fieldA: "fieldA string"
					`,
				},
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						numeric: 0
						fieldB: "fieldB string"
					`,
				},
			},
			Object: `
				type: Numeric
				numeric: 0
				fieldB: "fieldB string"
			`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.Test(unionFieldsParser); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnionErrors(t *testing.T) {
	tests := map[string]TestCase{
		"union_apply_two": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						numeric: 1
						string: "some string"
					`,
				},
			},
		},
		"union_apply_two_and_discriminator": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						type: Numeric
						string: "some string"
						numeric: 1
					`,
				},
			},
		},
		"union_apply_wrong_discriminator": {
			Ops: []Operation{
				Apply{
					Manager:    "default",
					APIVersion: "v1",
					Object: `
						type: Numeric
						string: "some string"
					`,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Test(unionFieldsParser) == nil {
				t.Fatal("Should fail")
			}
		})
	}
}
