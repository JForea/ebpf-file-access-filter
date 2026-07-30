#pragma once

#include <cstdint>

enum class Command : uint8_t {
    Unrecognized = 0,
    Help = 1,
    Add = 2,
    Remove = 3,
    View = 4,
    Clear = 5,
    Reload = 6,
};