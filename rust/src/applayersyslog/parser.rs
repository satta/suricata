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

use std::fmt;
use nom7::{IResult};
use nom7::bytes::complete::tag;
use nom7::character::complete::digit1;
use nom7::combinator::{complete, map_res, rest};
use std::str::FromStr;
use num_traits::FromPrimitive;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd, FromPrimitive, Debug)]
pub enum SyslogFacility {
    KERN = 0,
    USER = 1,
    MAIL = 2,
    SYSTEM = 3,
    SECURITY4 = 4,
    SYSLOG = 5,
    LPD = 6,
    NNTP = 7,
    UUCP = 8,
    TIME = 9,
    SECURITY10 = 10,
    FTPD = 11,
    NTPD = 12,
    LOGAUDIT = 13,
    LOGALERT = 14,
    CLOCK = 15,
    LOCAL0 = 16,
    LOCAL1 = 17,
    LOCAL2 = 18,
    LOCAL3 = 19,
    LOCAL4 = 20,
    LOCAL5 = 21,
    LOCAL6 = 22,
    LOCAL7 = 23,
    UNDEFINED0 = 24,
    UNDEFINED1 = 25,
    UNDEFINED2 = 26,
    UNDEFINED3 = 27,
    UNDEFINED4 = 28,
    UNDEFINED5 = 29,
    UNDEFINED6 = 30,
    UNDEFINED7 = 31,
}

impl SyslogFacility {
    pub fn to_lower_str(&self) -> String {
        self.to_string().to_lowercase()
    }
}

impl fmt::Display for SyslogFacility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd, FromPrimitive, Debug)]
pub enum SyslogSeverity {
    EMERGENCY = 0,
    ALERT = 1,
    CRITICAL = 2,
    ERROR = 3,
    WARNING = 4,
    NOTICE = 5,
    INFO = 6,
    DEBUG = 7,
}

impl SyslogSeverity {
    pub fn to_lower_str(&self) -> String {
        self.to_string().to_lowercase()
    }
}

impl fmt::Display for SyslogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct SyslogMessage {
    pub priority: Option<u8>,
    pub facility: Option<SyslogFacility>,
    pub severity: Option<SyslogSeverity>,
    pub version: Option<u8>,
    pub timestamp: Option<u64>,
    pub msg: String,
}




#[inline]
fn parse_syslog_priority(i: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    let (i, _) = tag("<")(i)?;
    let (i, pri) = map_res(map_res(digit1, std::str::from_utf8), u8::from_str)(i)?;
    let (i, _) = tag(">")(i)?;
    Ok ((i, (pri, pri >> 3, pri & 7)))
}

fn parse_syslog_udp(i: &[u8]) -> IResult<&[u8], SyslogMessage> {
    let (i, (pri, fac, sev)) = parse_syslog_priority(i)?;
    let (i, m) = rest(i)?;
    Ok((i, SyslogMessage{
        priority: Some(pri),
        facility: FromPrimitive::from_u8(fac),
        severity: FromPrimitive::from_u8(sev),
        version: None,
        timestamp: None,
        msg: String::from_utf8_lossy(m).to_string(),
    }))
}

pub fn parse_syslog_tcp(i: &[u8]) -> IResult<&[u8], SyslogMessage> {
     Ok((i, SyslogMessage{
        priority: None,
        facility: None,
        severity: None,
        version: None,
        timestamp: None,
        msg: "".to_string(),
    }))
}

pub fn parse_message_udp(input: &[u8]) -> IResult<&[u8], SyslogMessage> {
    return complete(parse_syslog_udp)(input);
}

pub fn parse_message_tcp(input: &[u8]) -> IResult<&[u8], SyslogMessage> {
    return parse_syslog_tcp(input);
}
