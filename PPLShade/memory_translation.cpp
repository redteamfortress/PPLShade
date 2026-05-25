// memory_translation.cpp - C++ file for memory map functionality
//#include "common.h"
#include "superfetch.h"
#include "memory_translation.h"
#pragma comment(lib, "ntdll.lib")
static spf::memory_map* g_memoryMap = NULL;

BOOL InitializeMemoryTranslation() {
    auto result = spf::memory_map::current();
    if (!result) {
        return FALSE;
    }
    g_memoryMap = new spf::memory_map(std::move(*result));
    return TRUE;
}

void CleanupMemoryTranslation() {
    if (g_memoryMap) {
        delete g_memoryMap;
        g_memoryMap = NULL;
    }
}

DWORD64 VirtualToPhysical(DWORD64 virtualAddress) {
    if (!g_memoryMap) {
        if (!InitializeMemoryTranslation()) {
            return 0;
        }
    }

    void const* virt_ptr = (void const*)virtualAddress;
    return g_memoryMap->translate(virt_ptr);
}