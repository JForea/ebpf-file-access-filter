# Ebpf file access filter

Ebpf Linux module for restricting access to user-specified files.

## Kernel-part building

Navigate to the kernel directory and run from command line:

```bash
make
```

## User application

### Building

Navigate to the user directory and run from command line:

```bash
cmake -S . -B build
cmake --build build
```

### Usage

First, you need to load previously built kernel-part. After the build navigate to user/build directory and use:

```bash
sudo faf-loader
```

Then you can use the application itself. There you'll see **faf** executable file. To run commands you need to run it with sudo. To see command list run the following command:

```bash
sudo faf help
```
