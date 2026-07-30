#include <iostream>

#include "Commands.hpp"
#include "Helpers.hpp"
#include "BpfHelpers.hpp"
#include "FileHelpers.hpp"

const std::string WrongUsage = "Wrong usage: faf [command]\n";

int main(int argc, char* argv[]){
    if (argc < 2 || argc > 3) {
        std::cerr << WrongUsage;
        return 1;
    }

    EnsureConfigFileExists();
    Command cmd = ParseCommand(argv[1]);

    try {
        switch (cmd) {
        case Command::Help:
            std::cout << "faf command list:\n" <<
                "help - view command list\n" <<
                "add [mask] - add new mask to driver\n" <<
                "remove [mask] - remove mask from driver\n" <<
                "view - view list of masks in driver\n" <<
                "clear - remove all masks from driver\n" <<
                "reload - clear all masks in driver and then load masks from config file\n";
            return 0;

        case Command::Add:
            if (argc != 3) {
                std::cerr << "Wrong usage: faf add [mask]\n";
                return 1;
            }

            AddMask(argv[2]);
            WriteMaskToFile(argv[2]);

            std::cout << "Added.\n";
            return 0;

        case Command::Remove:
            if (argc != 3) {
                std::cerr << "Wrong usage: faf remove [mask]\n";
                return 1;
            }

            RemoveMask(argv[2]);
            RemoveMaskFromFile(argv[2]);

            std::cout << "Removed.\n";
            return 0;

        case Command::View: {
            auto masks = ReadMasksFromFile();

            std::cout << "Current masks are:\n";
            for (std::string mask : masks)
                std::cout << mask << '\n';

            return 0;
        }

        case Command::Clear:
            ClearMasks();
            RemoveAllMasksFromFile();

            std::cout << "Cleared.\n";

            return 0;

        case Command::Reload: {
            ClearMasks();
            auto masks = ReadMasksFromFile();

            for (std::string mask : masks)
                AddMask(mask.c_str());

            std::cout << "Loaded.\n";

            return 0;
        }

        default:
            std::cerr << "Unknown command. Use 'faf help' for command list.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}