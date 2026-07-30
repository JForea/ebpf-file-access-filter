#pragma once

#include <string>
#include <vector>
#include <filesystem>

#include "Defaults.hpp"

void EnsureConfigFileExists(
    const std::filesystem::path& dir = ConfigDefaultDir,
    const std::string& filename = ConfigDefaultName
);

void WriteMaskToFile(const char* mask, const std::filesystem::path& path = ConfigDefaultDir/ConfigDefaultName);
void RemoveMaskFromFile(const char* mask, const std::filesystem::path& path = ConfigDefaultDir/ConfigDefaultName);
std::vector<std::string> ReadMasksFromFile(const std::filesystem::path& path = ConfigDefaultDir/ConfigDefaultName);
void RemoveAllMasksFromFile(const std::filesystem::path& path = ConfigDefaultDir/ConfigDefaultName);