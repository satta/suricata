#![feature(trace_macros)]
/* Copyright (C) 2020 Open Information Security Foundation
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

// Author: Frank Honza <frank.honza@dcso.de>



use std::fmt;
use nom::*;
use nom::number::streaming::*;

pub enum RFBGlobalState {
    TCServerProtocolVersion,
    TCSupportedSecurityTypes,
    TCVncChallenge,
    TCServerInit,
    TCFailureReason,
    TSClientProtocolVersion,
    TCServerSecurityType,
    TSSecurityTypeSelection,
    TSVncResponse,
    TCSecurityResult,
    TSClientInit,
    Message
}

impl fmt::Display for RFBGlobalState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RFBGlobalState::TCServerProtocolVersion => write!(f, "TCServerProtocolVersion"),
            RFBGlobalState::TCSupportedSecurityTypes => write!(f, "TCSupportedSecurityTypes"),
            RFBGlobalState::TCVncChallenge => write!(f, "TCVncChallenge"),
            RFBGlobalState::TCServerInit => write!(f, "TCServerInit"),
            RFBGlobalState::TCFailureReason => write!(f, "TCFailureReason"),
            RFBGlobalState::TSClientProtocolVersion => write!(f, "TSClientProtocolVersion"),
            RFBGlobalState::TSSecurityTypeSelection => write!(f, "TSSecurityTypeSelection"),
            RFBGlobalState::TSVncResponse => write!(f, "TSVncResponse"),
            RFBGlobalState::TCSecurityResult => write!(f, "TCSecurityResult"),
            RFBGlobalState::TCServerSecurityType => write!(f, "TCServerSecurityType"),
            RFBGlobalState::TSClientInit => write!(f, "TSClientInit"),
            RFBGlobalState::Message => write!(f, "Message")
        }
    }
}

#[derive(Debug)]
pub struct RFBStateInfo {
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u8
}

#[derive(Debug)]
pub struct ProtocolVersion {
    pub major: String,
    pub minor: String
}

#[derive(Debug)]
pub struct SupportedSecurityTypes {
    pub number_of_types: u8,
    pub types: Vec<u8>
}

#[derive(Debug)]
pub struct SecurityTypeSelection {
    pub security_type: u8
}

#[derive(Debug)]
pub struct ServerSecurityType {
    pub security_type: u32
}

#[derive(Debug)]
pub struct SecurityResult {
    pub status: u32
}

#[derive(Debug)]
pub struct FailureReason {
    pub reason_string: String
}

#[derive(Debug)]
pub struct VncAuth {
    pub secret: Vec<u8>
}

#[derive(Debug)]
pub struct ClientInit {
    pub shared: u8
}

#[derive(Debug)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian_flag: u8,
    pub true_colour_flag: u8,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

#[derive(Debug)]
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name_length: u32,
    pub name: Vec<u8>
}

#[derive(Debug)]
pub enum ClientServerMessage {
    SetPixelFormat(SetPixelFormatCSData),
    SetEncodings(SetEncodingsCSData),
    FramebufferUpdateRequest(FramebufferUpdateRequestCSData),
    KeyEvent(KeyEventCSData),
    PointerEvent(PointerEventCSData),
    ClientCutText(ClientCutTextCSData),
    Unassigned(u8)
}

#[derive(Debug)]
pub struct SetPixelFormatCSData {
    pub pixel_format: PixelFormat
}

#[derive(Debug)]
pub struct SetEncodingsCSData {
    pub encoding_types: Vec<i32>
}

#[derive(Debug)]
pub struct FramebufferUpdateRequestCSData {
    pub incremental: u8,
    pub xpos: u16,
    pub ypos: u16,
    pub width: u16,
    pub height: u16
}

#[derive(Debug)]
pub struct KeyEventCSData {
    pub down: bool,
    pub key: u32
}

#[derive(Debug)]
pub struct PointerEventCSData {
    pub buttonmask: u8,
    pub xpos: u16,
    pub ypos: u16
}

#[derive(Debug)]
pub struct ClientCutTextCSData {
    pub text: Vec<u8>
}

#[derive(Debug)]
pub enum ServerClientMessage {
    FramebufferUpdate(FramebufferUpdateSCData),
    SetColorMapEntries(SetColorMapEntriesSCData),
    Bell,
    ServerCutText(ServerCutTextSCData),
    Unassigned(u8)
}

#[derive(Debug)]
pub struct RawRectData {
    pub pixels: Vec<u8>
}

#[derive(Debug)]
pub struct CopyRectData {
    pub xpos: u16,
    pub ypos: u16
}

#[derive(Debug)]
pub struct RRESubrectData {
    pub pixel_value: Vec<u8>,
    pub xpos: u16,
    pub ypos: u16,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug)]
pub struct RRERectData {
    pub bg_pixel: Vec<u8>,
    pub subrectangles: Vec<RRESubrectData>
}

#[derive(Debug)]
pub struct HextileSubrect {
    pub pixel_value: Option<Vec<u8>>,
    pub xpos: u8,
    pub ypos: u8,
    pub width: u8,
    pub height: u8,
}

#[derive(Debug)]
pub struct HextileTile {
    pub width: u8,
    pub height: u8,
    pub SubencodingRaw: bool,
    pub SubencodingBackgroundSpecified: bool,
    pub SubencodingForegroundSpecified: bool,
    pub SubencodingAnySubrects: bool,
    pub SubencodingSubrectsColoured: bool,
    pub bg_pixel_value: Vec<u8>,
    pub fg_pixel_value: Vec<u8>,
    pub subrects: Vec<HextileSubrect>
}

#[derive(Debug)]
pub struct HextileRectData {
    pub tiles: Vec<HextileTile>
}

#[derive(Debug)]
pub struct ZRLERectData {
    // TODO decompress and parse further
    pub data: Vec<u8>
}


// TODO TRLE, ZRLE, pseudo-encodings
#[derive(Debug)]
pub enum RectangleData {
    Raw(RawRectData),
    CopyRect(CopyRectData),
    RRE(RRERectData),
    Hextile(HextileRectData),
    ZRLE(ZRLERectData)
}

#[derive(Debug)]
pub struct Rectangle {
    pub xpos: u16,
    pub ypos: u16,
    pub width: u16,
    pub height: u16,
    pub encoding_type: i32,
    pub data: RectangleData,
}

#[derive(Debug)]
pub struct FramebufferUpdateSCData {
    pub rectangles: Vec<Rectangle>
}

#[derive(Debug)]
pub struct RGBValue {
    pub red: u16,
    pub green: u16,
    pub blue: u16
}

#[derive(Debug)]
pub struct SetColorMapEntriesSCData {
    pub first_color: u16,
    pub colors: Vec<RGBValue>
}

#[derive(Debug)]
pub struct ServerCutTextSCData {
    pub text: Vec<u8>
}

named!(pub parse_protocol_version<ProtocolVersion>,
    do_parse!(
        _rfb_string: take_str!(3)
        >> be_u8
        >> major: take_str!(3)
        >> be_u8
        >> minor: take_str!(3)
        >> be_u8
        >> (
            ProtocolVersion{
                major: major.to_string(),
                minor: minor.to_string(),
            }
        )
    )
);

named!(pub parse_supported_security_types<SupportedSecurityTypes>,
    do_parse!(
        number_of_types: be_u8
        >> types: take!(number_of_types)
        >> (
            SupportedSecurityTypes{
                number_of_types: number_of_types,
                types: types.to_vec()
            }
        )
    )
);

named!(pub parse_server_security_type<ServerSecurityType>,
    do_parse!(
        security_type: be_u32
        >> (
            ServerSecurityType{
                security_type: security_type,
            }
        )
    )
);

named!(pub parse_vnc_auth<VncAuth>,
    do_parse!(
        secret: take!(16)
        >> (
            VncAuth {
                secret: secret.to_vec()
            }
        )
    )
);

named!(pub parse_security_type_selection<SecurityTypeSelection>,
    do_parse!(
        security_type: be_u8
        >> (
            SecurityTypeSelection {
                security_type: security_type
            }
        )
    )
);

named!(pub parse_security_result<SecurityResult>,
    do_parse!(
        status: be_u32
        >> (
            SecurityResult {
                status: status
            }
        )
    )
);

named!(pub parse_failure_reason<FailureReason>,
    do_parse!(
        reason_length: be_u32
        >> reason_string: take_str!(reason_length)
        >> (
            FailureReason {
                reason_string: reason_string.to_string()
            }
        )
    )
);

named!(pub parse_client_init<ClientInit>,
    do_parse!(
        shared: be_u8
        >> (
            ClientInit {
                shared: shared
            }
        )
    )
);

named!(pub parse_pixel_format<PixelFormat>,
    do_parse!(
        bits_per_pixel: be_u8
        >> depth: be_u8
        >> big_endian_flag: be_u8
        >> true_colour_flag: be_u8
        >> red_max: be_u16
        >> green_max: be_u16
        >> blue_max: be_u16
        >> red_shift: be_u8
        >> green_shift: be_u8
        >> blue_shift: be_u8
        >> take!(3)
        >> (
            PixelFormat {
                bits_per_pixel: bits_per_pixel,
                depth: depth,
                big_endian_flag: big_endian_flag,
                true_colour_flag: true_colour_flag,
                red_max: red_max,
                green_max: green_max,
                blue_max: blue_max,
                red_shift: red_shift,
                green_shift: green_shift,
                blue_shift: blue_shift,
            }
        )
    )
);

named!(pub parse_server_init<ServerInit>,
    do_parse!(
        width: be_u16
        >> height: be_u16
        >> pixel_format: parse_pixel_format
        >> name_length: be_u32
        >> name: take!(name_length)
        >> (
            ServerInit {
                width: width,
                height: height,
                pixel_format: pixel_format,
                name_length: name_length,
                name: name.to_vec()
            }
        )
    )
);

named!(pub parse_msg_type<u8>,
    do_parse!(
        msg_type: be_u8
        >> (
            msg_type
        )
    )
);

named!(pub parse_set_pixel_format<SetPixelFormatCSData>,
    do_parse!(
        take!(3)  // padding
        >> pixel_format: parse_pixel_format
        >> (
            SetPixelFormatCSData {
                pixel_format: pixel_format
            }
        )
    )
);

named!(pub parse_set_encodings<SetEncodingsCSData>,
    do_parse!(
        take!(1)  // padding
        >> number_of_encodings: be_u16
        >> encoding_types: count!(be_i32, number_of_encodings as usize)
        >> (
            SetEncodingsCSData {
                encoding_types: encoding_types
            }
        )
    )
);

named!(pub parse_fb_update_request<FramebufferUpdateRequestCSData>,
    do_parse!(
        incremental: be_u8
        >> xpos: be_u16
        >> ypos: be_u16
        >> width: be_u16
        >> height: be_u16
        >> (
            FramebufferUpdateRequestCSData {
                incremental: incremental,
                xpos: xpos,
                ypos: ypos,
                width: width,
                height: height
            }
        )
    )
);

named!(pub parse_key_event<KeyEventCSData>,
    do_parse!(
        down: be_u8
        >> take!(2)   // padding
        >> key: be_u32
        >> (
            KeyEventCSData {
                down: down != 0,
                key: key
            }
        )
    )
);

named!(pub parse_pointer_event<PointerEventCSData>,
    do_parse!(
        buttonmask: be_u8
        >> xpos: be_u16
        >> ypos: be_u16
        >> (
            PointerEventCSData {
                buttonmask: buttonmask,
                xpos: xpos,
                ypos: ypos
            }
        )
    )
);

named!(pub parse_client_cut_text<ClientCutTextCSData>,
    do_parse!(
        take!(3)   // padding
        >> text: length_data!(be_u32)
        >> (
            ClientCutTextCSData {
                text: text.to_vec()
            }
        )
    )
);

named!(pub parse_rgb_value<RGBValue>,
    do_parse!(
        red: be_u16
        >> green: be_u16
        >> blue: be_u16
        >> (
            RGBValue {
                red: red,
                green: green,
                blue: blue
            }
        )
    )
);

named!(pub parse_set_color_map_entries<SetColorMapEntriesSCData>,
    do_parse!(
        take!(1)   // padding
        >> firstcolor: be_u16
        >> number_of_rgbs: be_u16
        >> rgbs: count!(parse_rgb_value, number_of_rgbs as usize)
        >> (
            SetColorMapEntriesSCData {
                first_color: firstcolor,
                colors: rgbs
            }
        )
    )
);

named!(pub parse_server_cut_text<ServerCutTextSCData>,
    do_parse!(
        take!(3)   // padding
        >> text: length_data!(be_u32)
        >> (
            ServerCutTextSCData {
                text: text.to_vec()
            }
        )
    )
);

named!(pub parse_rectangle_data_zrle<RectangleData>,
    do_parse!(
        data: length_data!(be_u32)
        >> (
            RectangleData::ZRLE( ZRLERectData {
                data: data.to_vec()
            })
        )
    )
);

#[inline]
fn parse_hextile_tile_flags(i: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8, u8)> {
    bits!(
        i,
        tuple!(
            take_bits!(3u8),
            take_bits!(1u8),
            take_bits!(1u8),
            take_bits!(1u8),
            take_bits!(1u8)
        )
    )
}

#[inline]
fn parse_hextile_halfbytes(i: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    bits!(
        i,
        tuple!(
            take_bits!(4u8),
            take_bits!(4u8),
        )
    )
}

named_args!(pub parse_hextile_subrect(bpp: u8, coloured: bool)<RectangleData>,
    do_parse!(
        pixel_value: cond!(coloured, take!(bpp/8))
        >> xy_pos: parse_hextile_halfbytes
        >> width_height: parse_hextile_halfbytes
        >> (
            HextileSubrect {
                pixel_value: pixel_value,
                xpos: xy_pos.0,
                ypos: xy_pos.1,
                width: width_height.0,
                height: width_height.1
            }
        )
    )
);

pub fn parse_hextile_tile(input: &[u8], bpp: u8) -> IResult<&[u8], HextileTile> {
    match parse_hextile_tile_flags(input) => {

    }
}

pub fn parse_rectangle_data_hextile(input: &[u8], bpp: u8, width: u16, height: u16) -> IResult<&[u8], RectangleData> {
    let n_x_tiles = (width as f32 / 16.0).ceil() as u16;
    let n_y_tiles = (height as f32 / 16.0).ceil() as u16;
    SCLogNotice!("w {} h {}", n_x_tiles, n_y_tiles);

    let mut current = input;

    for n in 0..(n_y_tiles * n_x_tiles) {
        match parse_hextile_tile(current, bpp) {
            Ok((rem, tile)) => {

            }
            Err(e) => return Err(e)
        }
    }


    return Ok((input, RectangleData::Hextile(HextileRectData {
        tiles: Vec::new()
    })))
}

pub fn parse_rectangle_data(input: &[u8], etype: i32, bpp: u8, width: u16, height: u16) -> IResult<&[u8], RectangleData> {
    SCLogNotice!("parsing rectangle with type {:?}", etype);
    match etype {
        5 => {
            match parse_rectangle_data_hextile(input, bpp, width, height) {
                Ok((rect_rem, data)) => {
                    SCLogNotice!("parsed {:?} rects", data);
                    return Ok((rect_rem, data))
                 }
                 Err(e) => Err(e),
            }
        }
        16 => {
            match parse_rectangle_data_zrle(input) {
                Ok((rect_rem, data)) => {
                    SCLogNotice!("parsed {:?} rects", data);
                    return Ok((rect_rem, data))
                 }
                 Err(e) => Err(e),
            }
        }
        _ => {
            return Ok((&[], RectangleData::Raw(RawRectData{
                pixels: vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            })))
        }
    }
}

named_args!(pub parse_rectangle(bpp: u8, width: u16, height: u16)<Rectangle>,
    do_parse!(
        xpos: be_u16
        >> ypos: be_u16
        >> width: be_u16
        >> height: be_u16
        >> encoding_type: be_i32
        >> data: call!(parse_rectangle_data, encoding_type, bpp, width, height)
        >> (
            Rectangle {
                xpos: xpos,
                ypos: ypos,
                width: width,
                height: height,
                encoding_type: encoding_type,
                data: data
            }
        )
    )
);

named_args!(pub parse_fb_update(bpp: u8, width: u16, height: u16)<FramebufferUpdateSCData>,
    do_parse!(
        take!(1)   // padding
        >> rectangles: length_count!(be_u16, call!(parse_rectangle, bpp, width, height))
        >> (
            FramebufferUpdateSCData {
                rectangles: rectangles
            }
        )
    )
);

pub fn parse_ts_message<'a>(input: &'a [u8], state_info: &RFBStateInfo) -> IResult<&'a [u8], ClientServerMessage> {
    SCLogNotice!("parsing ts message len {}", input.len());
    match parse_msg_type(input) {
        Ok((rem, message_type)) => {
            SCLogNotice!("ts type {:?}", message_type);
            match message_type {
                0 => match parse_set_pixel_format(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::SetPixelFormat(data)))
                    }
                    Err(e) => Err(e),
                },
                2 => match parse_set_encodings(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::SetEncodings(data)))
                    }
                    Err(e) => Err(e),
                },
                3 => match parse_fb_update_request(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::FramebufferUpdateRequest(data)))
                    }
                    Err(e) => Err(e),
                },
                4 => match parse_key_event(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::KeyEvent(data)))
                    }
                    Err(e) => Err(e),
                },
                5 => match parse_pointer_event(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::PointerEvent(data)))
                    }
                    Err(e) => Err(e),
                },
                6 => match parse_client_cut_text(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ClientServerMessage::ClientCutText(data)))
                    }
                    Err(e) => Err(e),
                },
                _ => {
                    Ok((rem, ClientServerMessage::Unassigned(message_type)))
                }
            }
        }
        Err(err) => {
            return Err(err);
        }
    }
}

pub fn parse_tc_message<'a>(input: &'a [u8], state_info: &RFBStateInfo) -> IResult<&'a [u8], ServerClientMessage> {
    SCLogNotice!("parsing tc message len {}", input.len());
    match parse_msg_type(input) {
        Ok((rem, message_type)) => {
            SCLogNotice!("tc type {:?}", message_type);
            match message_type {
                0 => match parse_fb_update(rem, state_info.bits_per_pixel, state_info.width, state_info.height) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ServerClientMessage::FramebufferUpdate(data)))
                    }
                    Err(e) => Err(e),
                },
                1 => match parse_set_color_map_entries(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ServerClientMessage::SetColorMapEntries(data)))
                    }
                    Err(e) => Err(e),
                },
                2 =>  Ok((rem, ServerClientMessage::Bell)),
                3 => match parse_server_cut_text(rem) {
                    Ok((inner_rem, data)) => {
                       return  Ok((inner_rem, ServerClientMessage::ServerCutText(data)))
                    }
                    Err(e) => Err(e),
                },
                _ => {
                    Ok((rem, ServerClientMessage::Unassigned(message_type)))
                }
            }
        }
        Err(err) => {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::*;
    use super::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_version() {
        let buf = b"RFB 003.008\n";

        let result = parse_protocol_version(buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.major, "003");

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

    #[test]
    fn test_parse_server_init() {
        let buf = [
            0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01,
            0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e,
            0x61, 0x6e, 0x65, 0x61, 0x67, 0x6c, 0x65, 0x73,
            0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
            0x73, 0x74, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e
        ];

        let result = parse_server_init(&buf);
        match result {
            Ok((remainder, message)) => {
                // Check the first message.
                assert_eq!(message.width, 1280);
                assert_eq!(message.height, 800);
                assert_eq!(message.pixel_format.bits_per_pixel, 32);

                // And we should have 6 bytes left.
                assert_eq!(remainder.len(), 0);
            }
            Err(Err::Incomplete(_)) => {
                panic!("Result should not have been incomplete.");
            }
            Err(Err::Error(err)) |
            Err(Err::Failure(err)) => {
                panic!("Result should not be an error: {:?}.", err);
            }
        }
    }

}
