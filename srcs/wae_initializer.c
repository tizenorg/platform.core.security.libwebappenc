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
 * @file        wae_initializer.c
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       tool for importing APP DEKs during booting
 */

#include "key_handler.h"
#include "web_app_enc.h"
#include "wae_log.h"

int main(void)
{
    int ret = WAE_ERROR_NONE;
    ret = load_preloaded_app_deks();
    if(ret == WAE_ERROR_NONE) {
        WAE_SLOGI("WAE INITIALIZER was finished successfully.");
        return 0;
    }else {
        WAE_SLOGE("WAE INITIALIZER was finished with error. ret=%d", ret);
        return 0;
    }
}
