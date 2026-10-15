/* Original Pear finite control export. SPDX-License-Identifier: MIT. */
#include <stdarg.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "unixlib.h"
#include "pear_metal_protocol.h"
LONG WINAPI PearMetalPairingControl(struct pear_pairing_request *request)
{
    return MACDRV_CALL(pear_metal_pairing,request);
}
