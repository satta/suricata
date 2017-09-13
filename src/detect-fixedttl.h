/* Copyright (C) 2015-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 */

#ifndef __DETECT_FIXEDTTL_H__
#define __DETECT_FIXEDTTL_H__

/** Per keyword data. This is set up by the DetectFixedttlSetup() function.
 *  Each signature will have an instance of DetectFixedttlData per occurence
 *  of the keyword.
 *  The structure should be considered static/readonly after initialization.
 */
typedef struct DetectFixedttlData_ {
} DetectFixedttlData;

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectFixedttlRegister(void);

#endif /* __DETECT_FIXEDTTL_H__ */
