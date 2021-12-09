package ranges

import (
	"fmt"
	"math"
	"math/bits"
)

// An intRange represents a range of ints by its start and end values (inclusive)
type intRange struct {
	start uint32
	end   uint32
}

// for debugging
func (r intRange) String() string {
	return fmt.Sprintf("[ 0x%x, 0x%x ]", r.start, r.end)
}

// An intRangeMask represents a range of ints by its start and a mask value
type intRangeMask struct {
	start uint32
	mask  uint32
}

// for debugging
func (r intRangeMask) String() string {
	return fmt.Sprintf("0x%x/0x%x", r.start, r.mask)
}

// except returns a set of ranges equivalent to r with except removed
func (r intRange) except(except intRange) []intRange {
	switch {
	case r.start > except.end || r.end < except.start:
		// The range is either entirely after or entirely before the exception, so
		// keep the whole range.
		return []intRange{r}

	case r.start >= except.start && r.end <= except.end:
		// The exception completely overlaps the range, so omit the whole range.
		return nil
	}

	// At this point we know there is a partial, but not complete, overlap

	switch {
	case except.start <= r.start:
		// The exception starts before (or at) the range start, but does not
		// completely overlap the range, so keep the portion of the range after
		// the exception.
		return []intRange{
			{except.end + 1, r.end},
		}

	case except.end >= r.end:
		// The exception ends after (or at) the range end, but does not completely
		// overlap the range, so keep the portion of the range before the
		// exception.
		return []intRange{
			{r.start, except.start - 1},
		}
	}

	// At this point we know by process of elimination that the exception both starts
	// and ends inside the range (with at least one element of r on either side of
	// it), so split the range into the segment before the exception and the segment
	// after it.
	return []intRange{
		{r.start, except.start - 1},
		{except.end + 1, r.end},
	}
}

// toRangeMasks converts an intRange to an equivalent array of intRangeMasks
func (r intRange) toRangeMasks() []intRangeMask {
	rangeMasks := []intRangeMask{}

	// Repeatedly find the largest usable intRangeMask starting at start, then
	// update start to point to after that range mask, and loop until we reach
	// r.end.
	start := r.start
	for {
		rangeMask, rangeEnd := nextMask(start, r.end)
		rangeMasks = append(rangeMasks, rangeMask)

		if rangeEnd == r.end {
			// Reached the end
			break
		}
		start = rangeEnd + 1
	}

	return rangeMasks
}

// nextMask computes the mask and end value for the largest intRangeMask starting at start
// and ending at or before end.
func nextMask(start, end uint32) (intRangeMask, uint32) {
	// An intRangeMask covers a range from a starting value, to that value with some
	// consecutive number of its trailing "0" bits flipped to "1". Eg, if start is
	// 0xa120, then the intRangeMasks we can generate are:
	//
	//   { start = 0xa120, mask = 0xffe0 } => 0xa120 - 0xa13f (len = 32)
	//   { start = 0xa120, mask = 0xfff0 } => 0xa120 - 0xa12f (len = 16)
	//   { start = 0xa120, mask = 0xfff8 } => 0xa120 - 0xa127 (len = 8)
	//   { start = 0xa120, mask = 0xfffc } => 0xa120 - 0xa123 (len = 4)
	//   { start = 0xa120, mask = 0xfffe } => 0xa120 - 0xa121 (len = 2)
	//   { start = 0xa120, mask = 0xffff } => 0xa120 - 0xa120 (len = 1)
	//
	// The largest range we can generate is the one with a mask that flips every
	// trailing "0" bit in start to "1", which is to say, the mask that has "1" bits
	// up to the last "1" bit in start and "0" bits after that:
	//
	//     start    = 0xa120 = 0b1010000100100000
	//     mask     = 0xffe0 = 0b1111111111100000
	//     rangeEnd = 0xa13f = 0b1010000100111111
	//
	// (Any mask that doesn't have "1" bits up to the last "1" bit in start would
	// allow generating values that are *less than* start.)
	mask := uint32(math.MaxUint32) << bits.TrailingZeros32(start)
	rangeEnd := start ^ ^mask

	// If that ends within our range, then use it
	if rangeEnd <= end {
		return intRangeMask{start, mask}, rangeEnd
	}

	// OK, we need to find the intRangeMask with the largest power-of-2 length such
	// that (length <= end - start + 1). Eg, in the examples above, if end was 0x12a,
	// then the largest range we can use would be the 8 byte range from 0x120 to
	// 0x127. A power of 2 in binary is a number with a single "1" bit, and the
	// largest power of 2 less than or equal to (end - start + 1) is the number that
	// has a single "1" bit in the same position as the first "1" bit in (end - start
	// + 1). The mask to generate that power-of-2-length range is the one with "1"
	// bits up to that first "1" bit:
	//
	//     start       = 0xa120 = 0b1010000100100000
	//     end         = 0xa12a = 0b1010000100101010
	//     end-start+1 = 0x000b = 0b0000000000001011
	//     rangeLength = 0x0008 = 0b0000000000001000
	//     mask        = 0xfff8 = 0b1111111111111000
	//     rangeEnd    = 0xa127 = 0b1010000100100111
	maskLen := bits.LeadingZeros32(end-start+1) + 1
	mask = math.MaxUint32 << (32 - maskLen)
	rangeEnd = start ^ ^mask
	return intRangeMask{start, mask}, rangeEnd
}

// toRange converts an intRangeMask to an equivalent intRange
func (r intRangeMask) toRange() intRange {
	return intRange{
		start: r.start,
		end:   r.start ^ ^r.mask,
	}
}
