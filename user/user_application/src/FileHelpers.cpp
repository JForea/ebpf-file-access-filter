#include "FileHelpers.hpp"

#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <cerrno>

static const std::filesystem::path TempFilePath = ConfigDefaultDir/"masks.conf.temp";

void EnsureConfigFileExists(
    const std::filesystem::path& dir,
    const std::string& filename
) {
    if (mkdir(dir.c_str(), 0600) != 0) {
        if (errno != EEXIST)
            throw std::runtime_error("Couldn't create config directory.");
    }

    std::ofstream configFile(filename, std::ios::app);
}

void WriteMaskToFile(const char* mask, const std::filesystem::path& path) {
    std::ofstream out(path, std::ios::app);

    out << mask << '\n';
}

void RemoveMaskFromFile(const char* mask, const std::filesystem::path& path) {
    std::ifstream origin(path);
    std::ofstream temp(TempFilePath);

    std::string line;
    while (getline(origin, line)) {
        if (line != mask)
            temp << line << '\n';
    }

    remove(path);
    rename(TempFilePath, path);
}

std::vector<std::string> ReadMasksFromFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::vector<std::string> masks;

    std::string line;
    while (getline(in, line)) {
        masks.push_back(line);
    }

    return masks;
}

void RemoveAllMasksFromFile(const std::filesystem::path& path) {
    std::ofstream file(path, std::ios::trunc);
}