#pragma once

#include <string>
#include <filesystem>

#include "Commands.hpp"

Command ParseCommand(const std::string& s) noexcept;
std::filesystem::path GetMasksMapPath() noexcept;
