const std = @import("std");
const windows = std.os.windows;
const testing = std.testing;
const WORD = windows.WORD;
const DWORD = windows.DWORD;
const PVOID = windows.PVOID;
const ULONG_PTR = windows.ULONG_PTR;
const LDR_DATA_TABLE_ENTRY = windows.LDR_DATA_TABLE_ENTRY;
const PLDR_DATA_TABLE_ENTRY = *LDR_DATA_TABLE_ENTRY;
const BYTE = windows.BYTE;
const PBYTE = *BYTE;

const NtAllocateVirtualMemory_FnType = fn (hProcess: windows.HANDLE, ppBaseAddress: *?*anyopaque, zeroBits: usize, regionSize: *usize, allocType: u32, protect: u32) windows.NTSTATUS;
const NtProtectVirtualMemory_FnType = fn (hProcess: windows.HANDLE, ppBaseAddress: *?*anyopaque, regionSize: *usize, NewProtection: u32, OldProtection: *u32) windows.NTSTATUS;
const NtCreateThreadEx_FnType = fn (
    ThreadHandle: *?*windows.HANDLE,
    DesiredAccess: windows.ACCESS_MASK,
    ObjectAttributes: ?*windows.OBJECT_ATTRIBUTES,
    ProcessHandle: windows.HANDLE,
    StartRoutine: ?*anyopaque,
    Argument: ?*void,
    CreateFlags: bool,
    ZeroBits: ?*void,
    StackSize: ?*void,
    MaximumStackSize: ?*void,
    AttributeList: ?*void,
) windows.NTSTATUS;
const NtWaitForSingleObject_FnType = fn (
    handle: ?*windows.HANDLE,
    alertable: bool,
    timeout: ?*void,
) windows.NTSTATUS;
const NtOpenKey_FnType = fn (hProcess: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: *const windows.OBJECT_ATTRIBUTES) windows.NTSTATUS;

const NtAllocateVirtualMemory_Fn: *const NtAllocateVirtualMemory_FnType = @ptrCast(@extern(*const NtAllocateVirtualMemory_FnType, .{ .name = "RunSyscall" }));
const NtProtectVirtualMemory_Fn: *const NtProtectVirtualMemory_FnType = @ptrCast(@extern(*const NtProtectVirtualMemory_FnType, .{ .name = "RunSyscall" }));
const NtCreateThreadEx_Fn: *const NtCreateThreadEx_FnType = @ptrCast(@extern(*const NtCreateThreadEx_FnType, .{ .name = "RunSyscall" }));
const NtWaitForSingleObject_Fn: *const NtWaitForSingleObject_FnType = @ptrCast(@extern(*const NtWaitForSingleObject_FnType, .{ .name = "RunSyscall" }));
const NtOpenKey_Fn: *const NtOpenKey_FnType = @ptrCast(@extern(*const NtOpenKey_FnType, .{ .name = "RunSyscall" }));

pub fn run_NtAllocateVirtualMemory(hProcess: windows.HANDLE, ppBaseAddress: *?*anyopaque, zeroBits: usize, regionSize: *usize, allocType: u32, protect: u32) windows.NTSTATUS {
    SetSyscall(g_Nt.NtAllocateVirtualMemory) catch |err| {
        std.debug.print("SetSyscall failed: {}\n", .{err});
        return;
    };
    return NtAllocateVirtualMemory_Fn(hProcess, ppBaseAddress, zeroBits, regionSize, allocType, protect);
}

pub fn run_NtProtectVirtualMemory(hProcess: windows.HANDLE, ppBaseAddress: *?*anyopaque, regionSize: *usize, NewProtection: u32, OldProtection: *u32) windows.NTSTATUS {
    SetSyscall(g_Nt.NtProtectVirtualMemory) catch |err| {
        std.debug.print("SetSyscall failed: {}\n", .{err});
        return;
    };
    return NtProtectVirtualMemory_Fn(hProcess, ppBaseAddress, regionSize, NewProtection, OldProtection);
}

pub fn run_NtCreateThreadEx(
    ThreadHandle: *?*windows.HANDLE,
    DesiredAccess: windows.ACCESS_MASK,
    ObjectAttributes: ?*windows.OBJECT_ATTRIBUTES,
    ProcessHandle: windows.HANDLE,
    StartRoutine: ?*anyopaque,
    Argument: ?*void,
    CreateFlags: bool,
    ZeroBits: ?*void,
    StackSize: ?*void,
    MaximumStackSize: ?*void,
    AttributeList: ?*void,
) windows.NTSTATUS {
    SetSyscall(g_Nt.NtCreateThreadEx) catch |err| {
        std.debug.print("SetSyscall failed: {}\n", .{err});
        return;
    };
    return NtCreateThreadEx_Fn(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

pub fn run_NtWaitForSingleObject(
    handle: ?*windows.HANDLE,
    alertable: bool,
    timeout: ?*void,
) windows.NTSTATUS {
    SetSyscall(g_Nt.NtWaitForSingleObject) catch |err| {
        std.debug.print("SetSyscall failed: {}\n", .{err});
        return;
    };
    return NtWaitForSingleObject_Fn(handle, alertable, timeout);
}

pub fn run_NtOpenKey(hProcess: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: *const windows.OBJECT_ATTRIBUTES) windows.NTSTATUS {
    SetSyscall(g_Nt.NtAllocateVirtualMemory) catch |err| {
        std.debug.print("SetSyscall failed: {}\n", .{err});
        return;
    };
    return NtOpenKey_Fn(hProcess, DesiredAccess, ObjectAttributes);
}

pub const NtAllocateVirtualMemory_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtAllocateVirtualMemory".ptr)));
pub const NtProtectVirtualMemory_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtProtectVirtualMemory".ptr)));
pub const NtCreateThreadEx_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtCreateThreadEx".ptr)));
pub const NtWaitForSingleObject_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtWaitForSingleObject".ptr)));

pub const NtCreateFile_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtCreateFile".ptr)));
pub const NtCreateSection_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtCreateSection".ptr)));
pub const NtMapViewOfSection_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtMapViewOfSection".ptr)));
pub const NtUnmapViewOfSection_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtUnmapViewOfSection".ptr)));

pub const NtClose_CRC32: comptime_int = crc32b(@constCast(std.mem.span("NtClose".ptr)));
pub const NtOpenKey_CRC32 = crc32b(@constCast(std.mem.span("NtOpenKey".ptr)));

const c = @cImport({
    @cInclude("windows.h");
});

pub extern fn SetSSn(dwSSn: DWORD, pSyscallInstAddress: PVOID) void;
pub extern fn RunSyscall() void;

const NTDLL_CONFIG = struct {
    pdwArrayOfAddresses: [*]DWORD,
    pdwArrayOfNames: [*]DWORD,
    pwArrayOfOrdinals: [*]WORD,
    dwNumberOfNames: DWORD,
    uModule: ULONG_PTR,
};

const NT_SYSCALL = struct {
    dwSSn: DWORD,
    dwSyscallHash: DWORD,
    pSyscallAddress: ?PVOID,
    pSyscallInstAddress: ?PVOID,
};

const NTAPI_FUNC = struct { NtAllocateVirtualMemory: NT_SYSCALL, NtProtectVirtualMemory: NT_SYSCALL, NtCreateThreadEx: NT_SYSCALL, NtWaitForSingleObject: NT_SYSCALL, NtCreateFile: NT_SYSCALL, NtCreateSection: NT_SYSCALL, NtMapViewOfSection: NT_SYSCALL, NtUnmapViewOfSection: NT_SYSCALL, NtClose: NT_SYSCALL, NtOpenKey: NT_SYSCALL };

const SEED = 0xEDB88320;
const SEARCH_UP = -32;
const SEARCH_DOWN = 32;
const SEARCH_RANGE = 0xFF;

// global variable
pub var g_NtdllConf: NTDLL_CONFIG = undefined;
pub var g_Nt: NTAPI_FUNC = undefined;

inline fn setSyscall(ntSys: NT_SYSCALL) void {
    SetSSn(@intCast(ntSys.dwSSn), ntSys.pSyscallInstAddress);
}

pub fn crc32b(str: []u8) u32 {
    var crc: u32 = 0xFFFFFFFF;

    for (str) |byte| {
        crc ^= byte;

        var j: u8 = 0;
        while (j < 8) : (j += 1) {
            const mask = if ((crc & 1) != 0) @as(u32, 0xFFFFFFFF) else 0;
            crc = (crc >> 1) ^ (SEED & mask);
        }
    }

    return ~crc;
}

pub fn InitNtdllConfigStructure() bool {
    // getting peb
    const peb = std.os.windows.peb();

    if (peb.OSMajorVersion != 0xA) {
        std.debug.print("OS Major version is {}, can't continue, exiting\n", .{peb.OSMajorVersion});
        return false;
    }

    // getting ntdll.dll module (skipping our local image element)
    const pLdr: PLDR_DATA_TABLE_ENTRY = @ptrFromInt(@intFromPtr(@as(PBYTE, @ptrCast(peb.Ldr.InMemoryOrderModuleList.Flink.Flink))) - 0x10);
    // getting ntdll's base address
    const uModule: ULONG_PTR = @intFromPtr(pLdr.DllBase);

    if (uModule <= 0)
        return false;

    // fetching the dos header of ntdll
    const pImgDosHdr: *c.IMAGE_DOS_HEADER = @ptrFromInt(uModule);
    if (pImgDosHdr.e_magic != c.IMAGE_DOS_SIGNATURE)
        return false;

    const z1: usize = @intCast(pImgDosHdr.e_lfanew);

    // fetching the nt headers of ntdll
    const pImgNtHdrs: *c.IMAGE_NT_HEADERS = @ptrFromInt(uModule + z1);
    if (pImgNtHdrs.Signature != c.IMAGE_NT_SIGNATURE)
        return false;

    const va = pImgNtHdrs.OptionalHeader.DataDirectory[c.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const z2: usize = @intCast(va);

    // fetching the export directory of ntdll
    const pImgExpDir: ?*c.IMAGE_EXPORT_DIRECTORY = @ptrFromInt(uModule + z2);
    if (pImgExpDir == null)
        return false;

    // initalizing the 'g_NtdllConf' structure's element
    g_NtdllConf.uModule = uModule;
    g_NtdllConf.dwNumberOfNames = pImgExpDir.?.NumberOfNames;
    g_NtdllConf.pdwArrayOfNames = @ptrFromInt(uModule + @as(usize, pImgExpDir.?.AddressOfNames));
    g_NtdllConf.pdwArrayOfAddresses = @ptrFromInt(uModule + @as(usize, pImgExpDir.?.AddressOfFunctions));
    g_NtdllConf.pwArrayOfOrdinals = @ptrFromInt(uModule + @as(usize, pImgExpDir.?.AddressOfNameOrdinals));

    return true;
}

fn FetchNtSyscall(dwSysHash: DWORD, pNtSys: *NT_SYSCALL, verbose: bool) bool {
    if (dwSysHash > 0) {
        pNtSys.dwSyscallHash = dwSysHash;
    } else return false;

    for (0..g_NtdllConf.dwNumberOfNames) |i| {
        const pcFuncName = g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i];
        const cstr: [*:0]u8 = @as([*:0]u8, @ptrFromInt(pcFuncName));
        const zig_str: []u8 = std.mem.span(cstr);

        const pFuncAddress = g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]];

        if (crc32b(zig_str) == dwSysHash) {
            if (verbose) {
                std.debug.print("Found! {s} -> {x}\n", .{ zig_str, pFuncAddress });
            }

            pNtSys.pSyscallAddress = @as(*anyopaque, @ptrFromInt(pFuncAddress));

            const byte_array: [*]u8 = @ptrCast(pNtSys.pSyscallAddress);

            if (byte_array[0] == 0x4C and
                byte_array[1] == 0x8B and
                byte_array[2] == 0xD1 and
                byte_array[3] == 0xB8 and
                byte_array[6] == 0x00 and
                byte_array[7] == 0x00)
            {
                if (verbose) {
                    std.debug.print("Scenerio 1 catched\n", .{});
                }

                const high = byte_array[5];
                const low = byte_array[4];

                pNtSys.dwSSn = (@as(u16, high) << 8) | @as(u16, low);
                if (verbose) {
                    std.debug.print("SSN: {}\n", .{pNtSys.dwSSn});
                }

                break;
            } else {}
            if (byte_array[0] == 0xE9) {
                var b: usize = 1;
                while (b <= SEARCH_RANGE) : (b += 1) {
                    if (byte_array[0 + b * SEARCH_DOWN] == 0x4C and
                        byte_array[1 + b * SEARCH_DOWN] == 0x8B and
                        byte_array[2 + b * SEARCH_DOWN] == 0xD1 and
                        byte_array[3 + b * SEARCH_DOWN] == 0xB8 and
                        byte_array[6 + b * SEARCH_DOWN] == 0x00 and
                        byte_array[7 + b * SEARCH_DOWN] == 0x00)
                    {
                        if (verbose) {
                            std.debug.print("Scenerio 2 catched\n", .{});
                        }
                        const high = byte_array[5 + b * SEARCH_DOWN];
                        const low = byte_array[4 + b * SEARCH_DOWN];

                        pNtSys.dwSSn = (@as(u16, high) << 8) | @as(u16, low) - @as(u16, @truncate(b));
                        if (verbose) {
                            std.debug.print("SSN: {}\n", .{pNtSys.dwSSn});
                        }

                        break;
                    }
                    const addr = @intFromPtr(pNtSys.pSyscallAddress);
                    const byte_array2: [*]u8 = @ptrFromInt(addr - b * 8);
                    if (byte_array2[0 + b * SEARCH_DOWN] == 0x4C and
                        byte_array2[1 + b * SEARCH_DOWN] == 0x8B and
                        byte_array2[2 + b * SEARCH_DOWN] == 0xD1 and
                        byte_array2[3 + b * SEARCH_DOWN] == 0xB8 and
                        byte_array2[6 + b * SEARCH_DOWN] == 0x00 and
                        byte_array2[7 + b * SEARCH_DOWN] == 0x00)
                    {
                        if (verbose) {
                            std.debug.print("Scenerio 2 catched\n", .{});
                        }
                        const high = byte_array2[5 + b * SEARCH_DOWN];
                        const low = byte_array2[4 + b * SEARCH_DOWN];

                        pNtSys.dwSSn = (@as(u16, high) << 8) | @as(u16, low) + @as(u16, @truncate(b));
                        if (verbose) {
                            std.debug.print("SSN: {}\n", .{pNtSys.dwSSn});
                        }
                        break;
                    }
                }
            }
            if (byte_array[3] == 0xE9) {
                var b: usize = 1;
                while (b <= SEARCH_RANGE) : (b += 1) {
                    if (byte_array[0 + b * SEARCH_DOWN] == 0x4C and
                        byte_array[1 + b * SEARCH_DOWN] == 0x8B and
                        byte_array[2 + b * SEARCH_DOWN] == 0xD1 and
                        byte_array[3 + b * SEARCH_DOWN] == 0xB8 and
                        byte_array[6 + b * SEARCH_DOWN] == 0x00 and
                        byte_array[7 + b * SEARCH_DOWN] == 0x00)
                    {
                        if (verbose) {
                            std.debug.print("Scenerio 3 catched\n", .{});
                        }
                        const high = byte_array[5 + b * SEARCH_DOWN];
                        const low = byte_array[4 + b * SEARCH_DOWN];

                        pNtSys.dwSSn = (@as(u16, high) << 8) | @as(u16, low) - @as(u16, @truncate(b));
                        if (verbose) {
                            std.debug.print("SSN: {}\n", .{pNtSys.dwSSn});
                        }
                        break;
                    }
                    const addr = @intFromPtr(pNtSys.pSyscallAddress);
                    const byte_array2: [*]u8 = @ptrFromInt(addr - b * 8);
                    if (byte_array2[0 + b * SEARCH_DOWN] == 0x4C and
                        byte_array2[1 + b * SEARCH_DOWN] == 0x8B and
                        byte_array2[2 + b * SEARCH_DOWN] == 0xD1 and
                        byte_array2[3 + b * SEARCH_DOWN] == 0xB8 and
                        byte_array2[6 + b * SEARCH_DOWN] == 0x00 and
                        byte_array2[7 + b * SEARCH_DOWN] == 0x00)
                    {
                        if (verbose) {
                            std.debug.print("Scenerio 3 catched\n", .{});
                        }
                        const high = byte_array2[5 + b * SEARCH_DOWN];
                        const low = byte_array2[4 + b * SEARCH_DOWN];

                        pNtSys.dwSSn = (@as(u16, high) << 8) | @as(u16, low) + @as(u16, @truncate(b));
                        if (verbose) {
                            std.debug.print("SSN: {}\n", .{pNtSys.dwSSn});
                        }
                        break;
                    }
                }
            }
        } else {}
    }

    if (pNtSys.pSyscallAddress == null)
        return false;

    const uFuncAddress: ULONG_PTR = @intFromPtr(pNtSys.pSyscallAddress.?) + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    var z: usize = 0;
    while (z <= SEARCH_RANGE) : (z += 1) {
        const x: usize = z + 1;

        const ptr: [*]const u8 = @ptrFromInt(uFuncAddress);
        if (ptr[z] == 0x0F and ptr[x] == 0x05) {
            pNtSys.pSyscallInstAddress = @ptrFromInt(uFuncAddress + z);
            break;
        }
    }

    return true;
}

pub fn InitializeNtSyscalls(verbose: bool) bool {
    if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n", .{});
        return false;
    }
    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtCreateThreadEx Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtWaitForSingleObject Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtCreateFile_CRC32, &g_Nt.NtCreateFile, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtCreateFile \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtCreateFile Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtCreateFile.dwSSn, g_Nt.NtCreateFile.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtCreateSection_CRC32, &g_Nt.NtCreateSection, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtCreateSection \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtCreateSection Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtCreateSection.dwSSn, g_Nt.NtCreateSection.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtMapViewOfSection_CRC32, &g_Nt.NtMapViewOfSection, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtMapViewOfSection \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtMapViewOfSection Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtMapViewOfSection.dwSSn, g_Nt.NtMapViewOfSection.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtUnmapViewOfSection_CRC32, &g_Nt.NtUnmapViewOfSection, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtUnmapViewOfSection \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtUnmapViewOfSection Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtUnmapViewOfSection.dwSSn, g_Nt.NtUnmapViewOfSection.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtClose_CRC32, &g_Nt.NtClose, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtClose \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtClose Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress });
    }

    if (!FetchNtSyscall(NtOpenKey_CRC32, &g_Nt.NtOpenKey, verbose)) {
        std.debug.print("[!] Failed In Obtaining The Syscall Number Of NtOpenKey \n", .{});
        return false;
    }

    if (verbose) {
        std.debug.print("[+] Syscall Number Of NtOpenKey Is : 0x{x} \n\t\t>> Executing 'syscall' instruction Of Address : 0x{*}\n", .{ g_Nt.NtOpenKey.dwSSn, g_Nt.NtOpenKey.pSyscallInstAddress });
    }

    return true;
}

pub fn SetSyscall(syscall: NT_SYSCALL) !void {
    SetSSn(syscall.dwSSn, syscall.pSyscallInstAddress.?);
}

test "basic" {
    try testing.expect(InitNtdllConfigStructure() == true);
    try testing.expect(InitializeNtSyscalls(true) == true);
}
