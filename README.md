# SyringeEx

SyringeEx is a DLL injection and runtime hooking loader that launches a target executable and injects one or more hook DLLs into it.  
This fork extends and modernizes the original **Syringe** while maintaining compatibility with existing tooling and mods.

# License

The **entire program** is licensed under **LGPLv3**.  
See [`LICENSE`](LICENSE) for details.

The file **[`Syringe.h`](Syringe.h)** is explicitly designated as an **API header**, and may be used under the LGPLv3 interface rules.

# Background

Syringe was originally created by **Patrick "pd" Dinklage**, based partially on work by **Jan Newger**, and later maintained by contributors from the **Ares** project.

The original discussion thread is available [here](http://forums.renegadeprojects.com/showthread.php?tid=1160&pid=13088#pid13088).

# Command-Line Usage

### Executable Selection

The **first argument not starting with `-`** is treated as the executable to launch:

```
syringe.exe game.exe
```

### Passing Arguments to the Target Executable

Use `--args="..."` to provide arguments for the launched process:

```
syringe.exe game.exe --args="-CD. -SPAWN"
```

### DLL Injection Behavior

By default, Syringe injects **all compatible DLLs** found in the directory.

To load only specific DLLs, use one or more instances of:

```
-i=<dllname.dll>
```

Example:

```
syringe.exe game.exe -i=ExtensionA.dll -i=ExtensionB.dll
```

When at least one `-i=` option is present, **only the specified DLLs** are injected.

### Debugger Detach and Process Lifetime

By default, Syringe detaches its debugger automatically once all hooks have been placed, allowing the target process to continue execution normally.

This behavior can be modified using the following flags:

- `--nodetach`  
  Keeps the debugger attached after injection instead of detaching automatically.

- `--nowait`  
  Causes Syringe to exit immediately after detaching, without waiting for the target process to terminate.

By default (without `--nowait`), Syringe remains running after detaching and waits until the target process exits.

Example:

```
syringe.exe game.exe --nodetach
```

```
syringe.exe game.exe --nowait
```

These options can be combined to precisely control debugger lifetime and process synchronization behavior.

# Feature Flags API

SyringeEx uses a feature flags system to signal capability support to injected DLLs. This allows DLLs to verify that the running Syringe version supports the features they depend on, enabling version-aware behavior and graceful fallbacks for older installations.

Current closed-source version of Syringe is considered a baseline (SyringeEx has the features reimplemented, namely: multithreaded hook support, skipping handshakes that refuse Ares (Yuri's Revenge engine extension DLL) to load on Steam version of Yuri's Revenge). Everything beyond that must be declared as a feature flag, and DLLs that want to utilize the new features must check for the presence of required features before using them, and either refuse to load or provide fallback behavior if the features are not supported.

## How It Works

When a DLL is loaded, Syringe resolves exported boolean symbols from the `SyringeFeatures` namespace and sets them to `true` if the feature is supported. DLLs default these flags to `false`, so older Syringe versions that don't know about the flags will leave them unchanged.

## Using Feature Flags in Your DLL

```cpp
#include <Syringe.h>

void YourDLL::SomeLoadCode()
{
    if (SyringeFeatures::ZFPreservation)
    {
        // This Syringe version preserves the Zero Flag, so we can safely hook conditional instructions
    }
    else
    {
        // Fallback for older versions or bail out if this feature is critical
    }
}
```

## Current Feature Flags

- `ESPModification` - Adds an ability for DLLs to modify the stack pointer (ESP) across hooks to be able to exit on addresses with a different stack depth than the hook entry point
- `ZFPreservation` - Indicates that the Zero Flag (ZF) is preserved after hook execution, allowing to hook on conditional instructions

## Adding New API Features

All API enhancements beyond original Syringe must be declared as feature flags.

To add a new feature:

1. Add a new boolean to [`SyringeFeatures` namespace](include/Syringe.h)
2. Add the symbol name to `FeatureFlagNames[]` in [`SyringeDebugger.h`](SyringeDebugger.h)
3. Document the feature and its behavior in this README

