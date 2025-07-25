const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("ZigHellsHall", .{
        .root_source_file = b.path("src/hellshall.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addAssemblyFile(b.path("src/hellshall.s"));

    var main_tests = b.addTest(.{
        .root_source_file = b.path("src/hellshall.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&main_tests.step);
}
