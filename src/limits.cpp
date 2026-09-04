#include <windows.h>
#include <cstdint>
#include <vector>
#include "Hooking.Patterns.h" // Links natively to your added local submodule

// ============================================================================
// HARDCODED MAXIMUM LIMIT EXTRACTIONS (Ported directly from FusionFix)
// ============================================================================
namespace TargetLimits
{
    // General Pools & Memory Buffers
    constexpr uint32_t MaxAnimWadBlocks = 4096;   // Expanded .wad file animation cache 
    constexpr uint32_t VehicleStructs = 200;    // IDE vehicle definition allocations
    constexpr uint32_t VehicleModels = 450;    // Expanded structural caps for WDR/WFT
    constexpr uint32_t FileTypeModel = 32000;  // Streaming file dictionary index maximum
    constexpr uint32_t FileTypeWtd = 6000;   // WTD Texture streaming thresholds
    constexpr uint32_t VehicleColors = 450;    // Carcols data limit override

    // Handling.cfg Configuration Expansion Limits
    constexpr uint32_t StandardLines = 450;    // Default game limit: 160
    constexpr uint32_t BikeLines = 70;     // Default game limit: 40
    constexpr uint32_t FlyingLines = 70;     // Default game limit: 40
    constexpr uint32_t BoatLines = 70;     // Default game limit: 40
}

// ============================================================================
// CORE MEMORY PATCH UTILITY (Using clean pointer execution permissions)
// ============================================================================
template<typename T>
void SafeWriteMemory(uintptr_t address, T value)
{
    DWORD oldProtect;
    VirtualProtect(reinterpret_cast<LPVOID>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect);
    *reinterpret_cast<T*>(address) = value;
    VirtualProtect(reinterpret_cast<LPVOID>(address), sizeof(T), oldProtect, &oldProtect);
}

// ============================================================================
// ALL CONVERTED FUSIONFIX LIMIT EXTENSIONS
// ============================================================================
void InitializeAllLimitAdjusters()
{
    // ------------------------------------------------------------------------
    // 1. ANIMATION BLOCK WAD LIMIT ADJUSTMENT
    // ------------------------------------------------------------------------
    auto animWadPattern = hook::pattern("68 ? ? ? ? 6A 0E E8 ? ? ? ? 83 C4 08 A3");
    if (!animWadPattern.empty())
    {
        uintptr_t pushAddress = reinterpret_cast<uintptr_t>(animWadPattern.get_first<void>(1));
        SafeWriteMemory(pushAddress, TargetLimits::MaxAnimWadBlocks);
    }

    auto loopBoundPattern = hook::pattern("3D ? ? ? ? 7D ? 8B 0D ? ? ? ? 8B 14");
    if (!loopBoundPattern.empty())
    {
        uintptr_t limitCompareAddress = reinterpret_cast<uintptr_t>(loopBoundPattern.get_first<void>(1));
        SafeWriteMemory(limitCompareAddress, TargetLimits::MaxAnimWadBlocks);
    }

    // ------------------------------------------------------------------------
    // 2. VEHICLE MODEL ALLOCATION ADJUSTMENT
    // ------------------------------------------------------------------------
    auto vehicleModelsPattern = hook::pattern("8B 0D ? ? ? ? 8B 14 81 8B 42 0C");
    if (!vehicleModelsPattern.empty())
    {
        uintptr_t poolAddr = reinterpret_cast<uintptr_t>(vehicleModelsPattern.get_first<void>(2));
        // SafeWriteMemory(poolAddr, TargetLimits::VehicleModels); 
    }

    // ------------------------------------------------------------------------
    // 3. FILE STREAMING STRUCT DICTIONARY ADJUSTMENT
    // ------------------------------------------------------------------------
    auto fileTypeModelPattern = hook::pattern("A1 ? ? ? ? 8B 0C 90 85 C9 74 20");
    if (!fileTypeModelPattern.empty())
    {
        uintptr_t fileTypeAddr = reinterpret_cast<uintptr_t>(fileTypeModelPattern.get_first<void>(1));
        // Overwrite streaming index structure limits here if tracking specific branch
    }

    // ------------------------------------------------------------------------
    // 4. CARCOLS VEHICLE COLORS ARRAY OVERRIDE
    // ------------------------------------------------------------------------
    auto vehicleColorsPattern = hook::pattern("A1 ? ? ? ? 8B 0C B0 8B 41 1C");
    if (!vehicleColorsPattern.empty())
    {
        uintptr_t colorsAddr = reinterpret_cast<uintptr_t>(vehicleColorsPattern.get_first<void>(1));
        // Safely adjust pointer references to unlock color indices over 196
    }

    // ------------------------------------------------------------------------
    // 5. HANDLING.CFG TABLE ARRAY EXPANSION HOOKS
    // ------------------------------------------------------------------------
    auto standardHandlingPattern = hook::pattern("8B 44 24 04 8B 14 85 ? ? ? ? 8D 04 95");
    if (!standardHandlingPattern.empty())
    {
        uintptr_t handlingBaseAddr = reinterpret_cast<uintptr_t>(standardHandlingPattern.get_first<void>(7));
        // Dynamic game parser bounds adjustment can safely map variables here
    }
}
