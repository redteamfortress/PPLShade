// memory_translation.h - C compatible header
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	BOOL InitializeMemoryTranslation();
	void CleanupMemoryTranslation();
	DWORD64 VirtualToPhysical(DWORD64 virtualAddress);

#ifdef __cplusplus
}
#endif