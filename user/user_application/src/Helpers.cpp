#include "Helpers.hpp"

#include "defaults.h"

Command ParseCommand(const std::string& s) noexcept {
    if (s == "help")
        return Command::Help;
    if (s == "add")
        return Command::Add;
    if (s == "remove")
        return Command::Remove;
    if (s == "view")
        return Command::View;
    if (s == "clear")
        return Command::Clear;
    if (s == "reload")
        return Command::Reload;

    return Command::Unrecognized;
}

std::filesystem::path GetMasksMapPath() {
    std::filesystem::path path = bpf_folder_path;
    path /= masks_map_name;
    return path;
}