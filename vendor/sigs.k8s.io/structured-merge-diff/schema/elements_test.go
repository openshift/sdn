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

package schema

import (
	"reflect"
	"testing"
)

func TestFindNamedType(t *testing.T) {
	tests := []struct {
		testName      string
		defs          []TypeDef
		namedType     string
		expectTypeDef TypeDef
		expectExist   bool
	}{
		{"existing", []TypeDef{{Name: "a"}, {Name: "b"}}, "a", TypeDef{Name: "a"}, true},
		{"notExisting", []TypeDef{{Name: "a"}, {Name: "b"}}, "c", TypeDef{}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			s := Schema{
				Types: tt.defs,
			}
			td, exist := s.FindNamedType(tt.namedType)
			if !reflect.DeepEqual(td, tt.expectTypeDef) {
				t.Errorf("expected TypeDef %v, got %v", tt.expectTypeDef, td)
			}
			if exist != tt.expectExist {
				t.Errorf("expected existing %t, got %t", tt.expectExist, exist)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	existing := "existing"
	notExisting := "not-existing"
	a := Atom{List: &List{}}

	tests := []struct {
		testName       string
		schemaTypeDefs []TypeDef
		typeRef        TypeRef
		expectAtom     Atom
		expectExist    bool
	}{
		{"noNamedType", nil, TypeRef{Inlined: a}, a, true},
		{"notExistingNamedType", nil, TypeRef{NamedType: &notExisting}, Atom{}, false},
		{"existingNamedType", []TypeDef{{Name: existing, Atom: a}}, TypeRef{NamedType: &existing}, a, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			s := Schema{
				Types: tt.schemaTypeDefs,
			}
			atom, exist := s.Resolve(tt.typeRef)
			if !reflect.DeepEqual(atom, tt.expectAtom) {
				t.Errorf("expected Atom %v, got %v", tt.expectAtom, atom)
			}
			if exist != tt.expectExist {
				t.Errorf("expeted exist %t, got %t", tt.expectExist, exist)
			}
		})
	}
}
