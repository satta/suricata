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
use std::collections::VecDeque;
use crate::core::{ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP, IPPROTO_UDP};
use crate::applayer::{self, *};
use std::ffi::CString;
use nom7::Err;
use super::parser;

static mut ALPROTO_SYSLOG: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum SyslogEvent {}

#[derive(Debug)]
pub struct SyslogTransaction {
    tx_id: u64,
    pub request: Option<parser::SyslogMessage>,
    pub response: Option<parser::SyslogMessage>,

    tx_data: AppLayerTxData,
}

impl SyslogTransaction {
    pub fn new() -> SyslogTransaction {
        SyslogTransaction {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for SyslogTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

pub struct SyslogState {
    tx_id: u64,
    transactions: VecDeque<SyslogTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<SyslogTransaction> for SyslogState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&SyslogTransaction> {
        self.transactions.get(index)
    }
}

impl SyslogState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&SyslogTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> SyslogTransaction {
        let mut tx = SyslogTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut SyslogTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message_udp(start) {
                Ok((rem, request)) => {
                    start = rem;
                    SCLogNotice!("Request: {:?}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                    SCLogNotice!("txs: {:?}", self.transactions);
                },
                Err(Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                },
                Err(_) => {
                    return AppLayerResult::err();
                },
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while start.len() > 0 {
            match parser::parse_message_udp(start) {
                Ok((rem, response)) => {
                    start = rem;

                    match self.find_request() {
                        Some(tx) => {
                            tx.response = Some(response);
                            SCLogNotice!("Found response for request:");
                            SCLogNotice!("- Request: {:?}", tx.request);
                            SCLogNotice!("- Response: {:?}", tx.response);
                        }
                        None => {}
                    }
                }
                Err(Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

// C exports.

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_syslog_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
            return ALPROTO_SYSLOG;
    }
    
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_syslog_state_new(_orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto) -> *mut std::os::raw::c_void {
    let state = SyslogState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut std::os::raw::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut SyslogState));
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, SyslogState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
        true
    } else {
        false
    };

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, SyslogState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice,
    _data: *const std::os::raw::c_void
) -> AppLayerResult {
    let _eof = if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
        true
    } else {
        false
    };
    let state = cast_pointer!(state, SyslogState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, SyslogState);
    SCLogNotice!("get tx {:?}", tx_id);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, SyslogState);
    SCLogNotice!("get tx count {:?}", state.tx_id);
    return state.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    SCLogNotice!("get progress");
    return 2;
}

export_tx_data_get!(rs_syslog_get_tx_data, SyslogTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"syslog\0";

#[no_mangle]
pub unsafe extern "C" fn rs_syslog_register_parser() {
    let default_port = CString::new("[514]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_syslog_probing_parser),
        probe_tc: Some(rs_syslog_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_syslog_state_new,
        state_free: rs_syslog_state_free,
        tx_free: rs_syslog_state_tx_free,
        parse_ts: rs_syslog_parse_request,
        parse_tc: rs_syslog_parse_response,
        get_tx_count: rs_syslog_state_get_tx_count,
        get_tx: rs_syslog_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_syslog_tx_get_alstate_progress,
        get_eventinfo: Some(SyslogEvent::get_event_info),
        get_eventinfo_byid : Some(SyslogEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<SyslogState, SyslogTransaction>),
        get_tx_data: rs_syslog_get_tx_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_UNIDIR_TXS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_SYSLOG = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust syslog parser registered, alproto {:?}", alproto);
    } else {
        SCLogNotice!("Protocol detector and parser disabled for syslog.");
    }
}
