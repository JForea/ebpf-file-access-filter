#include "Helpers.hpp"

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
