#pragma once

#include <filesystem>
#include <bpf/bpf.h>

class BpfHelper {
private:
    int _fd{-1};

    static void ThrowIfNull(const char* mask);
    static size_t GetMaskLength(const char* mask);

    [[noreturn]]
    static void MapErrno(int error);

public:

    explicit BpfHelper(const std::string& path);

    BpfHelper(const BpfHelper&) = delete;
    BpfHelper& operator=(const BpfHelper&) = delete;

    void AddMask(const char* mask);
    void RemoveMask(const char* mask);
    void ClearMasks();

    ~BpfHelper() noexcept;
};
