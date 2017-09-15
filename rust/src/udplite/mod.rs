extern crate libc;

use std;

use nom::{be_u16};
use nom::*;

struct UdpliteHeader {
    sport: u16,
    dport: u16,
    coverage: u16,
    checksum: u16
}

named!(parse_header<UdpliteHeader>,
    do_parse!(
       sport: be_u16 >>
       dport: be_u16 >>
       coverage: be_u16 >>
       checksum: be_u16 >>
       (
           UdpliteHeader{
               sport: sport,
               dport: dport,
               coverage: coverage,
               checksum: checksum,
           }
        )
    )
);

#[no_mangle]
pub extern "C" fn rs_udplite_decode_coverage(input: *const libc::uint8_t,
                                             len: libc::uint32_t) -> i32 {
  let buf = unsafe{
    std::slice::from_raw_parts(input, len as usize)
  };
  match parse_header(buf) {
    IResult::Done(remaing, header) => {
        return header.coverage as i32;
    },
    IResult::Incomplete(needed) => {
        println!("more data needed: {:?}", needed);
    },
    IResult::Error(err) => {
        println!("error");
    }
  }
  return 0;
}

#[no_mangle]
pub extern "C" fn rs_udplite_decode_sport(input: *const libc::uint8_t,
                                             len: libc::uint32_t) -> i32 {
  let buf = unsafe{
    std::slice::from_raw_parts(input, len as usize)
  };
  match parse_header(buf) {
    IResult::Done(remaing, header) => {
        return header.sport as i32;
    },
    IResult::Incomplete(needed) => {
        println!("more data needed: {:?}", needed);
    },
    IResult::Error(err) => {
        println!("error");
    }
  }
  return 0;
}

#[no_mangle]
pub extern "C" fn rs_udplite_decode_dport(input: *const libc::uint8_t,
                                             len: libc::uint32_t) -> i32 {
  let buf = unsafe{
    std::slice::from_raw_parts(input, len as usize)
  };
  match parse_header(buf) {
    IResult::Done(remaing, header) => {
        return header.dport as i32;
    },
    IResult::Incomplete(needed) => {
        println!("more data needed: {:?}", needed);
    },
    IResult::Error(err) => {
        println!("error");
    }
  }
  return 0;
}

#[no_mangle]
pub extern "C" fn rs_udplite_decode_checksum(input: *const libc::uint8_t,
                                             len: libc::uint32_t) -> i32 {
  let buf = unsafe{
    std::slice::from_raw_parts(input, len as usize)
  };
  match parse_header(buf) {
    IResult::Done(remaing, header) => {
        return header.checksum as i32;
    },
    IResult::Incomplete(needed) => {
        println!("more data needed: {:?}", needed);
    },
    IResult::Error(err) => {
        println!("error");
    }
  }
  return 0;
}
