/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TIMEVAL_H
#define TIMEVAL_H 1

#include <time.h>
#include "openvswitch/type-props.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ds;
struct pollfd;
struct timespec;
struct timeval;

int time_poll(struct pollfd *, int, HANDLE *handles OVS_UNUSED, long long int, int *);
void timewarp_run(void);
long long int timespec_to_msec(const struct timespec *ts);
void xgettimeofday(struct timeval *tv);
void xclock_gettime(clock_t id, struct timespec *ts);
long long int time_msec(void);

#ifdef  __cplusplus
}
#endif

#endif /* timeval.h */
