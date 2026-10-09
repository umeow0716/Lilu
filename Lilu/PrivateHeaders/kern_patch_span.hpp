#ifndef LILU_PATCH_SPAN_HPP
#define LILU_PATCH_SPAN_HPP

// Full anchors are validated separately. Only changed bytes belong to the
// transaction's write/rollback range; unchanged overlapping context is safe.
namespace PatchSpan {
inline bool changed(const uint8_t *find, const uint8_t *replace, size_t size,
                    size_t &offset, size_t &length) {
	if (!find || !replace || !size) return false;
	offset = 0;
	while (offset < size && find[offset] == replace[offset]) ++offset;
	if (offset == size) return false;
	size_t end = size;
	while (end > offset && find[end-1] == replace[end-1]) --end;
	length = end-offset;
	return true;
}
}
#endif
