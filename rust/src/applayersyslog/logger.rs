/* Copyright (C) 2022 Open Information Security Foundation
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

use std;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use super::syslog::SyslogTransaction;

fn log_syslog(tx: &SyslogTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if let Some(ref request) = tx.request {
        if let Some(priority) = request.priority {
            js.set_uint("priority", priority.into())?;
        }
        if let Some(severity) = request.severity {
            js.open_object("severity")?;
            js.set_string("name", &severity.to_lower_str())?;
            js.set_uint("num", severity as u64)?;
            js.close()?;
        }
        if let Some(facility) = request.facility {
            js.open_object("facility")?;
            js.set_string("name", &facility.to_lower_str())?;
            js.set_uint("num", facility as u64)?;
            js.close()?;
        }
        js.set_string("msg", &request.msg)?;
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, SyslogTransaction);
    log_syslog(tx, js).is_ok()
}
