/* Copyright (C) 2015-2016 Open Information Security Foundation
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

#ifndef __DETECT_COVERAGE_H__
#define __DETECT_COVERAGE_H__

#define DETECT_COVERAGE_LT   0   /**< "less than" operator */
#define DETECT_COVERAGE_EQ   1   /**< "equals" operator (default) */
#define DETECT_COVERAGE_GT   2   /**< "greater than" operator */
#define DETECT_COVERAGE_RA   3   /**< "range" operator */

typedef struct DetectCoverageData_ {
    uint16_t csum1;
    uint16_t csum2;
    uint8_t mode;
} DetectCoverageData;

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectCoverageRegister(void);

#endif /* __DETECT_COVERAGE_H__ */
