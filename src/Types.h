#pragma once
#include <cstdint>

struct AnimationOverride
{
    //default to move_player
    uint32_t RifleAnimGroupID = 50;
    uint32_t RpgAnimGroupID = 50;
};

enum eAnimGroup
{
    ANIMGRP_MOVE_RIFLE = 50,
    ANIMGRP_MOVE_F_ARMED = 51,
    ANIMGRP_MOVE_RPG = 56,
};

enum CModelInfoStore
{
    ms_baseModels,
    ms_instanceModels,
    ms_timeModels,
    ms_weaponModels,
    ms_vehicleModels,
    ms_pedModels,
    ms_mloModels,
    ms_mlo,
    stru_F27FC4,
    ms_amat,
    ms_2dfxRefs1,
    ms_2dfxRefs2,
    ms_particleAttrs,
    ms_explosionAttrs,
    ms_procObjsAttrs,
    ms_ladderInfo,
    ms_spawnPointAttrs,
    ms_lightShaftAttrs,
    ms_scrollBars,
    ms_swayableAttrs,
    ms_bouyancyAttrs,
    ms_audioAttrs,
    ms_worldPointAttrs,
    ms_walkDontWalkAttrs,

    amount
};

struct CDataStore
{
    uint32_t nSize;
    uint32_t nAllocated;
    uint32_t pData;
};