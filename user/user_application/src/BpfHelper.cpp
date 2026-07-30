#include "BpfHelper.hpp"

#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <faf/filter_rule.h>

#include <unistd.h>
#include <linux/errno.h>

void BpfHelper::ThrowIfNull(const char* mask) {
    if (!mask)
        throw std::invalid_argument("Empty mask value.");
}

size_t BpfHelper::GetMaskLength(const char* mask) {
    size_t l = strlen(mask);

    if (l >= MAX_MASK_SIZE)
        throw std::runtime_error("Too long mask.");

    return l;
}

void BpfHelper::MapErrno(int error)
{
    std::string message;

    switch (error) {
    case ENOENT:
        message = "Mask not found.";
        break;

    case EEXIST:
        message = "Mask already exists.";
        break;

    case EBADF:
        message = "Invalid map file descriptor.";
        break;

    case EINVAL:
        message = "Invalid map operation or arguments.";
        break;

    default:
        message = std::strerror(error);
        break;
    }

    throw std::runtime_error(
        "Error during updating masks map: " + message);
}

BpfHelper::BpfHelper(const std::string& path) {
    _fd = bpf_obj_get(path.c_str());

    if (_fd < 0)
        throw std::runtime_error("Masks map not found.");
}

void BpfHelper::AddMask(const char* mask) {
    ThrowIfNull(mask);

    size_t maskLength = GetMaskLength(mask);
    filter_rule rule {};    

    char key[MAX_MASK_SIZE] {};

    memcpy(key, mask, maskLength);
    memcpy(rule.mask, mask, maskLength);

    rule.mask_size = maskLength;

    int err = bpf_map_update_elem(
        _fd,
        key,
        &rule,
        BPF_ANY
    );

    if (err < 0)
        MapErrno(errno);
}

void BpfHelper::RemoveMask(const char* mask) {
    ThrowIfNull(mask);

    char key[MAX_MASK_SIZE] {};
    size_t maskLength = GetMaskLength(mask);

    memcpy(key, mask, maskLength);

    int err = bpf_map_delete_elem(_fd, key);

    if (err < 0)
        MapErrno(errno);
}

void BpfHelper::ClearMasks() {
    char key[MAX_MASK_SIZE] {};

    while (bpf_map_get_next_key(_fd, nullptr, key) == 0) {
        if (bpf_map_delete_elem(_fd, key) < 0) {
            MapErrno(errno);
        }
    }

    if (errno != ENOENT) {
        MapErrno(errno);
    }
}

BpfHelper::~BpfHelper() noexcept {
    if (_fd >= 0)
        close(_fd);
}
