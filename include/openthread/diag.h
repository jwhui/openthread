/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @brief
 *   This file includes the OpenThread API for Factory Diagnostics.
 */

#ifndef OPENTHREAD_DIAG_H_
#define OPENTHREAD_DIAG_H_

#include <stdbool.h>
#include <stdint.h>

#include <openthread/error.h>
#include <openthread/instance.h>
#include <openthread/platform/diag.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-factory-diagnostics
 *
 * @brief
 *   This module includes functions that control the Thread stack's execution.
 *
 * @{
 */

/* Represents the pointer to callback to output diag messages. */
typedef otPlatDiagOutputCallback otDiagOutputCallback;

/**
 * Sets the diag output callback.
 *
 * @param[in]  aInstance   The OpenThread instance structure.
 * @param[in]  aCallback   A pointer to a function that is called on outputting diag messages.
 * @param[in]  aContext    A pointer to the user context.
 */
void otDiagSetOutputCallback(otInstance *aInstance, otDiagOutputCallback aCallback, void *aContext);

/**
 * Processes a factory diagnostics command line.
 *
 * @param[in]   aInstance       A pointer to an OpenThread instance.
 * @param[in]   aArgsLength     The number of elements in @p aArgs.
 * @param[in]   aArgs           An array of arguments.
 *
 * @retval  OT_ERROR_INVALID_ARGS       The command is supported but invalid arguments provided.
 * @retval  OT_ERROR_NONE               The command is successfully process.
 * @retval  OT_ERROR_NOT_IMPLEMENTED    The command is not supported.
 */
otError otDiagProcessCmd(otInstance *aInstance, uint8_t aArgsLength, char *aArgs[]);

/**
 * Processes a factory diagnostics command line.
 *
 * @param[in]   aInstance       A pointer to an OpenThread instance.
 * @param[in]   aString         A NULL-terminated input string.
 *
 * @retval  OT_ERROR_NONE               The command is successfully process.
 * @retval  OT_ERROR_INVALID_ARGS       The command is supported but invalid arguments provided.
 * @retval  OT_ERROR_NOT_IMPLEMENTED    The command is not supported.
 * @retval  OT_ERROR_NO_BUFS            The command string is too long.
 */
otError otDiagProcessCmdLine(otInstance *aInstance, const char *aString);

/**
 * Indicates whether or not the factory diagnostics mode is enabled.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 * @retval TRUE if factory diagnostics mode is enabled
 * @retval FALSE if factory diagnostics mode is disabled.
 */
bool otDiagIsEnabled(otInstance *aInstance);

/**
 * @}
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_DIAG_H_
