// Executes the production bounded reader with in-memory vnode fixtures.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <sys/types.h>
#define LILU_CACHE_HOST_TEST
struct Node { std::vector<uint8_t> bytes; };
using vnode_t = Node *;
using vfs_context_t = void *;
#define NULLVP nullptr
static std::map<std::string, Node> files;
static size_t largestRead, bytesRead, liveNodes;
static vfs_context_t vfs_context_create(void *) { return reinterpret_cast<void *>(1); }
static void vfs_context_rele(vfs_context_t) {}
static int vnode_lookup(const char *path, int, vnode_t *out, vfs_context_t) {
	auto it = files.find(path);
	if (it == files.end()) { *out = nullptr; return 1; }
	*out = &it->second; ++liveNodes; return 0;
}
static void vnode_put(vnode_t) { assert(liveNodes); --liveNodes; }
namespace FileIO {
static size_t readFileSize(vnode_t vnode, vfs_context_t) { return vnode->bytes.size(); }
static int readFileData(void *out, off_t offset, size_t size, vnode_t vnode, vfs_context_t) {
	if (offset < 0 || size_t(offset) > vnode->bytes.size() || size > vnode->bytes.size()-size_t(offset)) return 1;
	largestRead = std::max(largestRead, size); bytesRead += size;
	memcpy(out, vnode->bytes.data()+offset, size); return 0;
}
}
namespace Buffer {
template <typename T> static T *create(size_t count) { return new T[count] {}; }
template <typename T> static void deleter(T *p) { delete[] p; }
}
// Standard Mach-O wire structures; sizes are asserted below.
struct mach_header_64 { uint32_t magic; int32_t cputype, cpusubtype; uint32_t filetype, ncmds, sizeofcmds, flags, reserved; };
struct load_command { uint32_t cmd, cmdsize; };
struct segment_command_64 { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; int32_t maxprot, initprot; uint32_t nsects, flags; };
struct section_64 { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; };
static_assert(sizeof(mach_header_64) == 32 && sizeof(segment_command_64) == 72 && sizeof(section_64) == 80, "Mach-O fixture layout");
constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf, MH_DYLIB = 6, LC_SEGMENT_64 = 0x19;
constexpr int32_t CPU_TYPE_X86_64 = 0x1000007;
#include "../Lilu/PrivateHeaders/kern_cache.hpp"

static constexpr uint64_t base = 0x7ffa00100000;
static constexpr const char *cachePath = "/cache";
static constexpr const char *imagePath = "/System/Library/PrivateFrameworks/AppleGVA.framework/Versions/A/AppleGVA";
template <typename T> static void put(size_t offset, const T &value) {
	memcpy(files[cachePath].bytes.data()+offset, &value, sizeof(value));
}
static void fixture() {
	files.clear(); largestRead = bytesRead = 0; assert(!liveNodes);
	auto &bytes = files[cachePath].bytes; bytes.resize(0x4000);
	TahoeCache::Header header {};
	memcpy(header.magic, "dyld_v1  x86_64h", 16);
	header.mappingOffset = 0x200; header.mappingCount = 2;
	header.imagesOffset = 0x400; header.imagesCount = 1;
	put(0, header);
	put(0x200, TahoeCache::Mapping {base, 0x2000, 0x1000, 5, 5});
	put(0x220, TahoeCache::Mapping {base-0x10000, 0x1000, 0, 1, 1});
	put(0x400, TahoeCache::Image {base, 0, 0, 0x500, 0});
	memcpy(bytes.data()+0x500, imagePath, strlen(imagePath)+1);
	mach_header_64 mh {MH_MAGIC_64, CPU_TYPE_X86_64, 8, MH_DYLIB, 1, 152, 0, 0};
	put(0x1000, mh);
	segment_command_64 seg {};
	seg.cmd = LC_SEGMENT_64; seg.cmdsize = 152; memcpy(seg.segname, "__TEXT", 7);
	seg.vmaddr = base; seg.vmsize = seg.filesize = 0x2000; seg.fileoff = 0x1000; seg.nsects = 1;
	put(0x1020, seg);
	section_64 section {};
	memcpy(section.sectname, "__text", 7); memcpy(section.segname, "__TEXT", 7);
	section.addr = base+0x1000; section.size = 16; section.offset = 0x2000;
	put(0x1068, section);
	memset(bytes.data()+0x2000, 0x5a, 16);
}
static bool run() {
	size_t size = 123; uint64_t start = 123;
	uint64_t cacheBase = 0; uint8_t uuid[16] {};
	auto result = TahoeCache::readText(cachePath, imagePath, size, start, &cacheBase, uuid);
	assert(!liveNodes);
	if (!result) { assert(size == 0 && start == 0); return false; }
	assert(size == 0x2000 && start == base);
	assert(cacheBase == base-0x10000 && !memcmp(uuid, files[cachePath].bytes.data()+0x58, 16));
	auto seg = reinterpret_cast<segment_command_64 *>(result+32);
	auto section = reinterpret_cast<section_64 *>(result+104);
	assert(seg->fileoff == 0 && section->offset == 0x1000);
	for (size_t i = 0; i < 16; i++) assert(result[section->offset+i] == 0x5a);
	assert(largestRead <= 0x2000 && bytesRead < 0x10000);
	Buffer::deleter(result); return true;
}
int main() {
	fixture(); assert(run());
	fixture(); files[cachePath].bytes.resize(32); assert(!run());
	fixture(); put(0x1c4, uint32_t(32769)); assert(!run());
	fixture(); put(0x410, uint64_t(0)); put(0x418, uint32_t(0xfffffff0)); assert(!run());
	fixture(); put(0x1038, uint64_t(base+1)); assert(!run());
	fixture(); put(0x1040, uint64_t(17*1024*1024)); assert(!run());
	fixture(); put(0x1088, uint64_t(base+0x3000)); assert(!run());
	fixture(); put(0x1024, uint32_t(8)); assert(!run());
	// Source lives in a named subcache, not the main file.
	fixture();
	files["/cache.01"] = files[cachePath];
	put(0x200, TahoeCache::Mapping {base+0x4000, 0x1000, 0x1000, 5, 5});
	put(0x188, uint32_t(0x600)); put(0x18c, uint32_t(1));
	TahoeCache::SubCache sub {}; strcpy(sub.suffix, ".01"); put(0x600, sub);
	assert(run());
	files["/cache.01"].bytes[0x58] = 1; assert(!run());
	puts("PASS: bounded cache image, subcache UUID, truncation and Mach-O extent cases");
}
