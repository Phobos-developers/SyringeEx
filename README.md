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

