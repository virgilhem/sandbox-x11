# Introduction

This repository offers specialized scripts for creating secure, isolated environments in X11 systems. It aims to simplify the sandbox setup for various applications, enhancing security and compartmentalization.

## nestX

*nestX* is a script facilitating the launch of applications within an isolated X environment, created using `Xephyr`. It runs `bspwm`, a lightweight window manager, to improve interaction with the application GUI.

## sandboX

*sandboX* is a wrapper for `bwrap` ([Bubblewrap](https://github.com/containers/bubblewrap)), designed to streamline the creation of secure, isolated environments for applications. It enables users to customize isolation parameters through per-application configuration files.

**Key Features:**
- Modular Configuration: Allows the use of basic template files for consistent sandboxing across applications.
- D-Bus Filtering: Utilizes `xdg-dbus-proxy` to securely manage D-Bus access, preventing trivial sandbox escapes.
- AppImage Support: Enables running AppImages within isolated environment, leveraging sandboxing protections.

# Usage

Applications can be run in two modes.

**Sandbox only:**

    ./sandboX application

**Sandbox with Xephyr (recommended for network-facing applications):**

    ./nestX ./sandboX application

**Example**

Running a web browser in full isolation mode: `./nestX ./sandboX firefox`

See the provided **[firefox](/.config/bwrap/firefox)** configuration file.

# Setup

## Dependencies

The following binaries are assumed to be located in the `/usr/bin` directory:
- For *nestX*: `Xephyr`, `bspwm`, `wmctrl` (necessary for handling Xephyr closure events)
- For *sandboX*: `bwrap`, `xdg-dbus-proxy`, `fusermount` (from libfuse; necessary for AppImage support)
- Common Dependency: `xauth` (necessary for Xauthority-based access control)

## Configuration files ##

Users are encouraged to modify the provided examples or create new configuration files in the `$XDG_CONFIG_HOME/bwrap` directory.

The header line of a configuration file specifies the desired features for the sandboxed application, supported ones are `x11`, `dbus`, `appimage`, `net`, `1fd`, `nfd`. Subsequent lines are raw arguments to be passed to bwrap. Additional configuration file can be included using `inc` option, specific arguments can be adjusted with `del`.

The **[_x_skeleton](/.config/bwrap/_x_skeleton)** template file should be suitable for most applications.

## BPF filters ##

The default cBPF program is located at `$XDG_CONFIG_HOME/bwrap/bpf/seccomp_default_filter.bpf`. It blocks a default set of privileged syscalls, including TIOCSTI ioctl in order to prevent terminal command injection.

> [!WARNING]
> This filter operates under a default-allow policy, which suits most use-cases but poses a security risk. Users are advised to implement per-application filters that only allow a predefined list of syscalls.

Custom cBPF programs must be named following the pattern *seccomp_**application_name**_filter.bpf*.

## AppImages ##

By default, AppImages are searched for in the `/opt/appimages` directory. The ".appimage" extension must be removed from the filename, and the AppImage must be renamed consistently with the configuration file.
