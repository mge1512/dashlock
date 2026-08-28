/*
 * dashlock.h - Landlock self-confinement for dash.
 *
 * Copyright (c) 2026 Matthias G. Eckermann.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This header is deliberately free of any dependency on the rest of the
 * shell.  dashlock runs as the first statement of main(), before init(),
 * and main.h redefines errno as (*dash_errno) for glibc while dash_errno
 * itself is only assigned inside main().  Including any shell header here
 * would put an uninitialised pointer dereference on the startup path.
 */

#ifndef DASHLOCK_H
#define DASHLOCK_H

/*
 * Exit status used for every refusal.  78 is EX_CONFIG from sysexits.h,
 * chosen because it does not collide with the shell's own exit statuses
 * (2 for a usage error, 126 and 127 for exec failures).
 */
#define DASHLOCK_EXIT_CONFIG 78

#ifdef USE_DASHLOCK

/*
 * Called as the first statement of main().  Returns without side effects
 * unless the binary was invoked under the configured trigger name.  When it
 * does act, it either applies the policy or terminates the process; it never
 * returns with a partially applied domain.
 *
 * argv is modified in place when a leading "--narrow NAME" pair is consumed;
 * *argcp is decremented by two in that case so that the argc/argv contract
 * the shell relies on is preserved.
 */
void dashlock_init(int *, char **);

#else

static inline void dashlock_init(int *argcp, char **argv)
{
	(void)argcp;
	(void)argv;
}

#endif /* USE_DASHLOCK */

#endif /* DASHLOCK_H */
