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
 *   This file includes the platform abstraction for the microsecond alarm service.
 */

#ifndef OPENTHREAD_PLATFORM_ALARM_MICRO_H_
#define OPENTHREAD_PLATFORM_ALARM_MICRO_H_

#include <stdint.h>

#include <openthread/instance.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup plat-alarm
 *
 * @{
 */

/**
 * Set the alarm to fire at @p aDt microseconds after @p aT0.
 *
 * For @p aT0, the platform MUST support all values in [0, 2^32-1].
 * For @p aDt, the platform MUST support all values in [0, 2^31-1].
 *
 * @param[in]  aInstance  The OpenThread instance structure.
 * @param[in]  aT0        The reference time.
 * @param[in]  aDt        The time delay in microseconds from @p aT0.
 */
void otPlatAlarmMicroStartAt(otInstance *aInstance, uint32_t aT0, uint32_t aDt);

/**
 * Stop the alarm.
 *
 * @param[in] aInstance  The OpenThread instance structure.
 */
void otPlatAlarmMicroStop(otInstance *aInstance);

/**
 * Get the current time.
 *
 * The current time MUST represent a free-running timer. When maintaining current time, the time value MUST utilize the
 * entire range [0, 2^32-1] and MUST NOT wrap before 2^32.
 *
 * @returns  The current time in microseconds.
 */
uint32_t otPlatAlarmMicroGetNow(void);

/**
 * Signal that the alarm has fired.
 *
 * @param[in] aInstance  The OpenThread instance structure.
 */
extern void otPlatAlarmMicroFired(otInstance *aInstance);

/**
 * @}
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPENTHREAD_PLATFORM_ALARM_MICRO_H_
