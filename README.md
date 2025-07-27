# How to use

Add following to build.zig.zon (Hash will change, in order to get the correct hash remove the hash section and build the project, you should get the correct hash)

```zig
.dependencies = .{
    .ZigHellsHall = .{ .url = "https://github.com/KcanCurly/zighellshall/archive/refs/tags/vX.X.X.zip", .hash = "hellshall-A.B.C-HASH" },
    }
```

Add following to build.zig

```zig
const hellshall_dep = b.dependency("ZigHellsHall", .{ .target = target, .optimize = optimize }); \
const hellshall_mod = hellshall_dep.module("ZigHellsHall"); \
exe_mod.addImport("hellshall", hellshall_mod); 
```

Add following to main.zig

```zig
const hellshall = @import("hellshall");
const is_init = hellshall.InitNtdllConfigStructure();
if (is_init) {
    _ = hellshall.InitializeNtSyscalls(false);
}
```

# Credits
[Maldev Academy](https://maldevacademy.com/)