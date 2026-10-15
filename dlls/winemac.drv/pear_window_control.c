/* Original Pear finite Stage 5 PE control. SPDX-License-Identifier: MIT. */
#include <stdarg.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "unixlib.h"
#include "stage5_protocol.h"
LONG WINAPI PearStage5Control(pear_s5_request *request)
{
    return MACDRV_CALL(pear_stage5, request);
}
