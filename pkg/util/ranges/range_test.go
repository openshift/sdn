package ranges

import (
	"reflect"
	"testing"
)

func Test_intRange_except(t *testing.T) {
	ranges := []intRange{
		{
			start: 17,
			end:   135,
		},
	}

	// Note that the tests are cumulative
	for i, tc := range []struct {
		except intRange
		result []intRange
	}{
		{
			except: intRange{
				start: 20,
				end:   40,
			},

			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   135,
				},
			},
		},
		{
			except: intRange{
				start: 130,
				end:   140,
			},

			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   129,
				},
			},
		},
		{
			except: intRange{
				start: 100,
				end:   109,
			},

			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   99,
				},
				{
					start: 110,
					end:   129,
				},
			},
		},
		{
			except: intRange{
				start: 105,
				end:   200,
			},

			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   99,
				},
			},
		},
		{
			except: intRange{
				start: 80,
				end:   99,
			},
			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   79,
				},
			},
		},
		{
			except: intRange{
				start: 100,
				end:   200,
			},
			result: []intRange{
				{
					start: 17,
					end:   19,
				},
				{
					start: 41,
					end:   79,
				},
			},
		},
	} {
		newRanges := []intRange{}
		for _, r := range ranges {
			newRanges = append(newRanges, r.except(tc.except)...)
		}
		ranges = newRanges
		if !reflect.DeepEqual(ranges, tc.result) {
			t.Fatalf("bad result for %d\nexpected %v\ngot      %v", i, tc.result, ranges)
		}
	}
}
