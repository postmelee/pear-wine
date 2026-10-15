/* Original Pear Stage 3 negative fixture, SPDX-License-Identifier: MIT.
 * The generated import library names a nonexistent named or ordinal export
 * from the owned lifetime DLL. Loading must fail before DllMain executes.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllimport) int WINAPI PearMissing(void);
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return PearMissing() == 0;
}
