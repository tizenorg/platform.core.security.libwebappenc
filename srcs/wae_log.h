/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        wae-log.h
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       a header for loggin.
 */

#ifndef __WAE_LOG_H__
#define __WAE_LOG_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <unistd.h>

/* Use DLOG logging mechanism */
#include "dlog.h"

#define TAG_WAE           "WAE"

#define WAE_SLOGD(format, arg...) SLOG(LOG_DEBUG, TAG_WAE, format, ##arg)
#define WAE_SLOGI(format, arg...) SLOG(LOG_INFO,  TAG_WAE, format, ##arg)
#define WAE_SLOGW(format, arg...) SLOG(LOG_WARN,  TAG_WAE, format, ##arg)
#define WAE_SLOGE(format, arg...) SLOG(LOG_ERROR, TAG_WAE, format, ##arg)
#define WAE_SLOGF(format, arg...) SLOG(LOG_FATAL, TAG_WAE, format, ##arg)

#endif /* __WAE_LOG_H__*/

