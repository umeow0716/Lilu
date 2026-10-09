// Bounded, read-only modern dyld cache access. No cache-sized allocations.
#ifndef kern_cache_hpp
#define kern_cache_hpp

#ifndef LILU_CACHE_HOST_TEST
#include <Headers/kern_file.hpp>
#include <mach-o/loader.h>
#include <sys/vnode.h>
#endif

namespace TahoeCache {
struct Header {
	char magic[16];
	uint32_t mappingOffset, mappingCount;
	uint8_t reserved18[0x40];
	uint8_t uuid[16];
	uint8_t reserved68[0x120];
	uint32_t subCacheOffset, subCacheCount;
	uint8_t reserved190[0x30];
	uint32_t imagesOffset, imagesCount;
};
static_assert(offsetof(Header, uuid) == 0x58, "cache UUID layout");
static_assert(offsetof(Header, subCacheOffset) == 0x188, "subcache layout");
static_assert(offsetof(Header, imagesOffset) == 0x1c0, "image directory layout");
struct Mapping { uint64_t address, size, offset; uint32_t maxProt, initProt; };
struct Image { uint64_t address, modTime, inode; uint32_t pathOffset, pad; };
struct SubCache { uint8_t uuid[16]; uint64_t vmOffset; char suffix[32]; };

class File {
	vnode_t vnode {NULLVP};
	vfs_context_t context {nullptr};
	size_t length {0};
public:
	Header header {};
	File() = default;
	File(const File &) = delete;
	File &operator=(const File &) = delete;
	~File() {
		if (vnode) vnode_put(vnode);
		if (context) vfs_context_rele(context);
	}
	bool read(uint64_t offset, void *out, size_t size) const {
		return vnode && offset <= length && size <= length-offset &&
		       !FileIO::readFileData(out, static_cast<off_t>(offset), size, vnode, context);
	}
	bool open(const char *path, const uint8_t *uuid = nullptr) {
		context = vfs_context_create(nullptr);
		if (!context || vnode_lookup(path, 0, &vnode, context)) return false;
		length = FileIO::readFileSize(vnode, context);
		if (!read(0, &header, sizeof(header)) || memcmp(header.magic, "dyld_v1", 7) ||
		    header.mappingOffset < sizeof(header) || !header.mappingCount ||
		    header.mappingCount > 32 || header.subCacheCount > 64 ||
		    header.imagesCount > 32768 || (uuid && memcmp(uuid, header.uuid, 16))) return false;
		return true;
	}
	bool readVM(uint64_t address, void *out, size_t size) const {
		for (uint32_t i = 0; i < header.mappingCount; i++) {
			Mapping mapping {};
			if (!read(uint64_t(header.mappingOffset)+uint64_t(i)*sizeof(mapping), &mapping, sizeof(mapping))) return false;
			if (address < mapping.address || address-mapping.address > mapping.size) continue;
			auto delta = address-mapping.address;
			if (size > mapping.size-delta || mapping.offset > UINT64_MAX-delta) continue;
			return read(mapping.offset+delta, out, size);
		}
		return false;
	}
};

// Read an address range from one UUID-qualified main/subcache mapping.
inline bool readVM(File &main, const char *cachePath, uint64_t address, void *out, size_t size) {
	if (main.readVM(address, out, size)) return true;
	for (uint32_t i = 0; i < main.header.subCacheCount; i++) {
		SubCache entry {};
		if (!main.read(uint64_t(main.header.subCacheOffset)+uint64_t(i)*sizeof(entry), &entry, sizeof(entry))) return false;
		// Tahoe uses explicit subcache suffixes. Never guess numbered legacy names.
		if (entry.suffix[0] != '.' || !memchr(entry.suffix, 0, sizeof(entry.suffix)) ||
		    strchr(entry.suffix, '/') || strstr(entry.suffix, "..")) return false;
		char path[512] {};
		if (strlen(cachePath)+strlen(entry.suffix) >= sizeof(path)) return false;
		snprintf(path, sizeof(path), "%s%s", cachePath, entry.suffix);
		File sub;
		if (!sub.open(path, entry.uuid)) return false;
		if (sub.readVM(address, out, size)) return true;
	}
	return false;
}

// Materialise only __TEXT with section file offsets rebased for MachInfo.
// The returned bytes are read-only reference data, never written to the cache.
inline uint8_t *readText(const char *cachePath, const char *imagePath, size_t &size, uint64_t &start,
                         uint64_t *cacheBase = nullptr, uint8_t *cacheUUID = nullptr) {
	size = 0; start = 0;
	File main;
	if (!main.open(cachePath) || !main.header.imagesOffset || !main.header.imagesCount) return nullptr;
	uint64_t headerAddress = 0;
	for (uint32_t i = 0; i < main.header.mappingCount; i++) {
		Mapping mapping {};
		if (!main.read(uint64_t(main.header.mappingOffset)+uint64_t(i)*sizeof(mapping), &mapping, sizeof(mapping))) return nullptr;
		if (!mapping.offset && mapping.size >= sizeof(Header)) {
			if (headerAddress) return nullptr;
			headerAddress = mapping.address;
		}
	}
	if ((cacheBase || cacheUUID) && !headerAddress) return nullptr;
	uint64_t imageAddress = 0;
	const size_t pathLength = strlen(imagePath)+1;
	if (pathLength > 512) return nullptr;
	for (uint32_t i = 0; i < main.header.imagesCount; i++) {
		Image image {};
		char path[512] {};
		if (!main.read(uint64_t(main.header.imagesOffset)+uint64_t(i)*sizeof(image), &image, sizeof(image)) ||
		    !main.read(image.pathOffset, path, pathLength)) return nullptr;
		if (!memcmp(path, imagePath, pathLength)) {
			if (imageAddress) return nullptr;
			imageAddress = image.address;
		}
	}
	if (!imageAddress || imageAddress > UINT64_MAX-65536) return nullptr;
	mach_header_64 mh {};
	if (!readVM(main, cachePath, imageAddress, &mh, sizeof(mh)) || mh.magic != MH_MAGIC_64 ||
	    mh.cputype != CPU_TYPE_X86_64 || mh.filetype != MH_DYLIB || !mh.ncmds || mh.ncmds > 256 ||
	    mh.sizeofcmds > 65536-sizeof(mh)) return nullptr;
	auto commands = Buffer::create<uint8_t>(mh.sizeofcmds);
	if (!commands) return nullptr;
	uint64_t textSize = 0;
	bool valid = readVM(main, cachePath, imageAddress+sizeof(mh), commands, mh.sizeofcmds);
	size_t offset = 0;
	for (uint32_t i = 0; valid && i < mh.ncmds; i++) {
		if (offset > mh.sizeofcmds || sizeof(load_command) > mh.sizeofcmds-offset) { valid = false; break; }
		auto lc = reinterpret_cast<load_command *>(commands+offset);
		if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > mh.sizeofcmds-offset) { valid = false; break; }
		if (lc->cmd == LC_SEGMENT_64) {
			if (lc->cmdsize < sizeof(segment_command_64)) { valid = false; break; }
			auto seg = reinterpret_cast<segment_command_64 *>(lc);
			if (!strncmp(seg->segname, "__TEXT", sizeof(seg->segname))) {
				if (textSize || seg->vmaddr != imageAddress || seg->vmsize > 16*1024*1024 ||
				    seg->vmsize > UINT64_MAX-imageAddress ||
				    seg->vmsize < sizeof(mh)+mh.sizeofcmds || seg->nsects >
				    (lc->cmdsize-sizeof(*seg))/sizeof(section_64)) { valid = false; break; }
				textSize = seg->vmsize;
				seg->fileoff = 0; seg->filesize = textSize;
				auto sections = reinterpret_cast<section_64 *>(seg+1);
				for (uint32_t j = 0; j < seg->nsects; j++) {
					if (sections[j].addr < imageAddress || sections[j].addr-imageAddress > textSize ||
					    sections[j].size > textSize-(sections[j].addr-imageAddress)) { valid = false; break; }
					sections[j].offset = static_cast<uint32_t>(sections[j].addr-imageAddress);
				}
			}
		}
		offset += lc->cmdsize;
	}
	valid = valid && textSize && offset == mh.sizeofcmds;
	// The validated 16 MiB ceiling also fits the retained i386 build.
	auto boundedSize = static_cast<size_t>(textSize);
	auto result = valid ? Buffer::create<uint8_t>(boundedSize) : nullptr;
	if (result && readVM(main, cachePath, imageAddress, result, boundedSize)) {
		memcpy(result+sizeof(mh), commands, mh.sizeofcmds);
		size = boundedSize; start = imageAddress;
		if (cacheBase) *cacheBase = headerAddress;
		if (cacheUUID) memcpy(cacheUUID, main.header.uuid, 16);
	} else if (result) { Buffer::deleter(result); result = nullptr; }
	Buffer::deleter(commands);
	return result;
}
}
#endif
