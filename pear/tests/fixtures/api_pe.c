/* Original Pear Stage 3 fixture, SPDX-License-Identifier: MIT.
 * No C runtime or proprietary content. Kernel32 calls exercise real Wine APIs.
 * The runner supplies an empty, owned current directory and scoped environment.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

/* Pinned Wine winnt.h defines a 4-byte architecture entry: low 16 bits are
 * Machine; the high bits are Kernel/User/Native/Process/WoW64/reserved flags.
 * Query class 181 matches the actual Wineboot capability request. */
typedef LONG (NTAPI *query_architectures_fn)(ULONG, void *, ULONG, void *, ULONG, ULONG *);
typedef ULONG (NTAPI *status_to_error_fn)(LONG);
static DWORD architecture_words[8], architecture_status, architecture_terminator;
static ULONG architecture_bytes;
static unsigned architecture_count;
static int architecture_queried;
_Static_assert(sizeof(DWORD) == 4, "Architecture entries require four-byte DWORDs");

static const WCHAR arg_space[] = L"space argument";
static const WCHAR arg_unicode[] = L"\u03a9\ud55c\uae00\U0001f680";
static const WCHAR env_value[] = L"pear value \u03a9\ud55c\uae00\U0001f680";
static const WCHAR owned_name[] = L"pear api \u03a9.dat";
static const WCHAR missing_name[] = L"pear missing \u03a9.dat";
static const unsigned char payload[] = {0, 1, 2, 127, 128, 255, 'P', 'e', 'a', 'r', '\n', 0, 42};
static WCHAR command[2048], words[4][768], executable[1024], child_command[1400];
static unsigned checks, error_step;
static DWORD error_code, child_exit;
static uint64_t payload_hash;

static unsigned wlen(const WCHAR *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int equal(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

/* Restricted fixture grammar: quoted or unquoted tokens, no embedded quotes or
 * backslash escapes. Reject unclosed quotes, oversized input and extra tokens.
 * This is not a replacement for general Windows command-line parsing.
 */
static unsigned arguments(void)
{
    const WCHAR *source = GetCommandLineW();
    unsigned length = 0, count = 0, at = 0;
    while (source[length] && length < 2047) { command[length] = source[length]; ++length; }
    if (source[length]) return 0;
    command[length] = 0;
    while (at < length) {
        unsigned out = 0;
        int quote = 0;
        while (command[at] == ' ' || command[at] == '\t') ++at;
        if (!command[at]) break;
        if (count == 4) return 0;
        if (command[at] == '"') { quote = 1; ++at; }
        while (command[at] && (quote ? command[at] != '"' : command[at] != ' ' && command[at] != '\t')) {
            if (out == 767 || command[at] == '"') return 0;
            words[count][out++] = command[at++];
        }
        if (quote && command[at++] != '"') return 0;
        if (command[at] && command[at] != ' ' && command[at] != '\t') return 0;
        words[count++][out] = 0;
    }
    return count;
}

static int fail_code(unsigned step, DWORD code)
{
    if (!error_step) { error_step = step; error_code = code; }
    return 0;
}

static int fail(unsigned step) { return fail_code(step, GetLastError()); }

static uint64_t hash_bytes(const unsigned char *bytes, unsigned size)
{
    uint64_t value = UINT64_C(14695981039346656037);
    for (unsigned i = 0; i < size; ++i) { value ^= bytes[i]; value *= UINT64_C(1099511628211); }
    return value;
}

static int basics(unsigned count, int child)
{
    WCHAR environment[64];
    unsigned first = child ? 2 : 1;
    if (count != first + 2 || !equal(words[first], arg_space) || !equal(words[first + 1], arg_unicode)) return fail(1);
    checks |= 1;
    DWORD length = GetEnvironmentVariableW(L"PEAR_API_INPUT", environment, 64);
    if (length != wlen(env_value) || !equal(environment, env_value)) return fail(2);
    checks |= 2;
    unsigned char *allocation = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocation) return fail(3);
    int valid = 1;
    for (unsigned i = 0; i < 4096; ++i) if (allocation[i] != 0) valid = 0;
    for (unsigned i = 0; i < 4096; ++i) allocation[i] = (unsigned char)(i * 17 + 3);
    for (unsigned i = 0; i < 4096; ++i) if (allocation[i] != (unsigned char)(i * 17 + 3)) valid = 0;
    if (!valid) fail_code(3, ERROR_INVALID_DATA);
    if (!VirtualFree(allocation, 0, MEM_RELEASE)) fail(3);
    if (error_step) return 0;
    checks |= 4;
    DWORD slot = TlsAlloc();
    if (slot == TLS_OUT_OF_INDEXES) return fail(4);
    SetLastError(ERROR_SUCCESS);
    valid = 1;
    if (TlsGetValue(slot) != NULL) valid = fail_code(4, ERROR_INVALID_DATA);
    else if (GetLastError() != ERROR_SUCCESS) valid = fail(4);
    if (!TlsSetValue(slot, words)) valid = fail(4);
    else {
        void *observed = TlsGetValue(slot);
        DWORD code = GetLastError();
        if (observed != words)
            valid = fail_code(4, !observed && code != ERROR_SUCCESS ? code : ERROR_INVALID_DATA);
    }
    if (!TlsFree(slot)) valid = fail(4);
    if (!valid) return 0;
    checks |= 8;
    return 1;
}

static int files(void)
{
    unsigned char received[sizeof(payload) + 1];
    DWORD count = 0;
    HANDLE file = CreateFileW(owned_name, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return fail(5);
    int valid = WriteFile(file, payload, sizeof(payload), &count, NULL);
    if (!valid) fail(5);
    else if (count != sizeof(payload)) valid = fail_code(5, ERROR_INVALID_DATA);
    if (valid) {
        SetLastError(ERROR_SUCCESS);
        DWORD position = SetFilePointer(file, 0, NULL, FILE_BEGIN);
        DWORD code = GetLastError();
        if (position != 0)
            valid = fail_code(5, position == INVALID_SET_FILE_POINTER && code ? code : ERROR_INVALID_DATA);
    }
    if (valid) {
        valid = ReadFile(file, received, sizeof(received), &count, NULL);
        if (!valid) fail(5);
        else if (count != sizeof(payload)) valid = fail_code(5, ERROR_INVALID_DATA);
    }
    if (valid) {
        payload_hash = hash_bytes(received, count);
        if (payload_hash != hash_bytes(payload, sizeof(payload))) valid = fail_code(5, ERROR_INVALID_DATA);
    }
    if (!CloseHandle(file)) valid = fail(5);
    if (!DeleteFileW(owned_name)) { fail(7); return 0; }
    checks |= 64;
    if (!valid) return 0;
    checks |= 16;
    file = CreateFileW(missing_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD observed = GetLastError();
    if (file != INVALID_HANDLE_VALUE) {
        fail_code(6, ERROR_INVALID_DATA);
        CloseHandle(file);
        return 0;
    }
    if (observed != ERROR_FILE_NOT_FOUND) return fail_code(6, observed);
    checks |= 32;
    return 1;
}

static int append(WCHAR *destination, unsigned capacity, const WCHAR *source)
{
    unsigned at = wlen(destination), length = wlen(source);
    if (at + length + 1 > capacity) return 0;
    for (unsigned i = 0; i <= length; ++i) destination[at + i] = source[i];
    return 1;
}

static int child_roundtrip(void)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD length = GetModuleFileNameW(NULL, executable, 1024);
    if (!length || length >= 1024) return fail(8);
    for (DWORD i = 0; i < length; ++i) if (executable[i] == '"') return fail(8);
    if (!append(child_command, 1400, L"\"") || !append(child_command, 1400, executable) ||
        !append(child_command, 1400, L"\" --child \"space argument\" \"") ||
        !append(child_command, 1400, arg_unicode) || !append(child_command, 1400, L"\"")) return fail(8);
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessW(executable, child_command, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT,
                        NULL, NULL, &startup, &process)) return fail(8);
    int valid = CloseHandle(process.hThread);
    if (!valid) fail(8);
    DWORD wait_result = WaitForSingleObject(process.hProcess, 15000);
    if (wait_result != WAIT_OBJECT_0) {
        if (wait_result == WAIT_FAILED) fail(8);
        else fail_code(8, wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_INVALID_DATA);
        if (!TerminateProcess(process.hProcess, 99) || WaitForSingleObject(process.hProcess, 3000) != WAIT_OBJECT_0)
            valid = 0;
    } else if (!GetExitCodeProcess(process.hProcess, &child_exit)) valid = fail(8);
    else if (child_exit != 37) valid = fail_code(8, ERROR_INVALID_DATA);
    if (!CloseHandle(process.hProcess)) valid = fail(8);
    if (!valid || error_step) return 0;
    checks |= 128;
    return 1;
}

static char output[512];
static unsigned output_length;
static void text(const char *s) { while (*s && output_length < sizeof(output) - 1) output[output_length++] = *s++; }
static void number(uint64_t value)
{
    char reverse[21]; unsigned length = 0;
    do { reverse[length++] = '0' + value % 10; value /= 10; } while (value);
    while (length) output[output_length++] = reverse[--length];
}
static int report(int child)
{
    text("{\"version\":1,\"record_kind\":\"pear_api_result\",\"role\":\"");
    text(child ? "child" : "parent");
    text("\",\"checks_bitmask\":"); number(checks);
    text(",\"error_step\":"); number(error_step);
    text(",\"win32_error\":"); number(error_code);
    text(",\"fnv1a64\":\"");
    const char hex[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) output[output_length++] = hex[(payload_hash >> shift) & 15];
    text("\",\"child_exit\":"); number(child_exit); text("}\n");
    DWORD written = 0;
    return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_length, &written, NULL) && written == output_length;
}

static int architecture_check(void)
{
    HANDLE process = NULL;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return fail(9);
    query_architectures_fn query = (query_architectures_fn)(uintptr_t)GetProcAddress(ntdll, "NtQuerySystemInformationEx");
    if (!query) return fail(9);
    status_to_error_fn convert = (status_to_error_fn)(uintptr_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!convert) return fail(9);
    for (unsigned i = 0; i < 8; ++i) architecture_words[i] = UINT32_MAX;
    architecture_bytes = 0;
    architecture_count = 0;
    architecture_terminator = UINT32_MAX;
    LONG status = query(181, &process, sizeof(process), architecture_words,
                        sizeof(architecture_words), &architecture_bytes);
    architecture_queried = 1;
    architecture_status = (DWORD)status;
    if (status < 0) return fail_code(9, convert(status));
    if (architecture_bytes < 8 || architecture_bytes > sizeof(architecture_words) || architecture_bytes % 4)
        return fail_code(9, ERROR_INVALID_DATA);
    for (unsigned i = 0; i < architecture_bytes / 4; ++i) {
        if (!architecture_words[i]) { architecture_terminator = 0; break; }
        ++architecture_count;
    }
    if (status != 0 || architecture_bytes != 8 || architecture_count != 1 ||
        architecture_words[0] != (0xAA64u | (7u << 16)) || architecture_terminator != 0)
        return fail_code(9, ERROR_INVALID_DATA);
    return 1;
}

static int architecture_report(void)
{
    if (!architecture_queried) return 1;
    output_length = 0;
    text("{\"version\":1,\"record_kind\":\"pear_architecture_result\",\"status\":");
    number(architecture_status);
    text(",\"returned_bytes\":"); number(architecture_bytes);
    text(",\"machines\":[");
    for (unsigned i = 0; i < architecture_count; ++i) {
        if (i) text(",");
        number(architecture_words[i] & 0xffffu);
    }
    text("],\"flags\":[");
    for (unsigned i = 0; i < architecture_count; ++i) {
        if (i) text(",");
        number(architecture_words[i] >> 16);
    }
    text("],\"terminator\":"); number(architecture_terminator); text("}\n");
    DWORD written = 0;
    int valid = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_length, &written, NULL) && written == output_length;
    output_length = 0;
    return valid;
}

void WINAPI mainCRTStartup(void)
{
    unsigned count = arguments();
    int child = count > 1 && equal(words[1], L"--child");
    int valid = basics(count, child);
    if (valid && !child) {
        valid = architecture_check();
        if (!architecture_report()) ExitProcess(90);
        if (valid) valid = files() && child_roundtrip();
    }
    if (!report(child)) ExitProcess(90);
    ExitProcess(valid ? (child ? 37 : 0) : 91);
}
