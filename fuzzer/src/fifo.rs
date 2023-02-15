use nix::unistd;
use nix::sys::stat;
//use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::collections::VecDeque;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use byteorder::{LittleEndian, ReadBytesExt};
use std::{
    fs::File,
    io::{self, Read},
};


// additional info for gep
pub struct GepMsg {
  pub ptr_label: u32,
  pub index_label: u32,
  pub ptr: u64,
  pub index: i64,
  pub num_elems: u64,
  pub elem_size: u64,
  pub current_offset: u64,
}

impl GepMsg {
  pub fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
    let ptr_label = rdr.read_u32::<LittleEndian>()?;
    let index_label  = rdr.read_u32::<LittleEndian>()?;
    let ptr  = rdr.read_u64::<LittleEndian>()?;
    let index = rdr.read_i64::<LittleEndian>()?;
    let num_elems  = rdr.read_u64::<LittleEndian>()?;
    let elem_size  = rdr.read_u64::<LittleEndian>()?;
    let current_offset  = rdr.read_u64::<LittleEndian>()?;

    Ok(GepMsg{
        ptr_label,
        index_label,
        ptr,
        index,
        num_elems,
        elem_size,
        current_offset,
        })
  }
}


pub struct PipeMsg {
  pub msgtype: u16, //gep, cond, add_constraints, strcmp
  pub flags: u16, 
  pub tid: u32,
  pub addr: u64,
  pub ctx: u32,
  pub id: u32, //branch id
  pub label: u32,
  pub result: u64, //direction for conditional branch, index for GEP
}

impl PipeMsg {
  pub fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
    let msgtype = rdr.read_u16::<LittleEndian>()?;
    let flags  = rdr.read_u16::<LittleEndian>()?;
    let tid = rdr.read_u32::<LittleEndian>()?;
    let addr = rdr.read_u64::<LittleEndian>()?;
    let ctx = rdr.read_u32::<LittleEndian>()?;
    let id = rdr.read_u32::<LittleEndian>()?;
    let label = rdr.read_u32::<LittleEndian>()?;
    let result = rdr.read_u64::<LittleEndian>()?;

    Ok(PipeMsg{
        msgtype,
        flags,
        tid,
        addr,
        ctx,
        id,
        label,
        result,
        })
  }
}

pub fn make_pipe() {
  match unistd::mkfifo("/tmp/wp", stat::Mode::S_IRWXU) {
    Ok(_) => println!("created"),
    Err(err) => println!("Error creating fifo: {}", err),
  }
}

/*
pub fn read_pipe(piped: RawFd) -> (Vec<(u32,u32,u64,u64,u64,u32,u32)>, VecDeque<[u8;1024]>) {
  let f = unsafe { File::from_raw_fd(piped) };
  let mut reader = BufReader::new(f);
  let mut ret = Vec::new();
  let mut retdata = VecDeque::new();
  loop {
    let mut buffer = String::new();
    let num_bytes = reader.read_line(&mut buffer).expect("read pipe failed");
    //if not EOF
    if num_bytes !=0  {
      let tokens: Vec<&str> = buffer.trim().split(',').collect();
      let tid = tokens[0].trim().parse::<u32>().expect("we expect u32 number in each line");
      let label = tokens[1].trim().parse::<u32>().expect("we expect u32 number in each line");
      let direction = tokens[2].trim().parse::<u64>().expect("we expect u32 number in each line");
      let addr = tokens[3].trim().parse::<u64>().expect("we expect u64 number in each line");
      let ctx = tokens[4].trim().parse::<u64>().expect("we expect u64 number in each line");
      let order = tokens[5].trim().parse::<u32>().expect("we expect u32 number in each line");
      let isgep = tokens[6].trim().parse::<u32>().expect("we expect u32 number in each line");
      ret.push((tid,label,direction,addr,ctx,order,isgep));
      if isgep == 2 {
        let mut buffer = String::new();
        let num_bytes = reader.read_line(&mut buffer).expect("read pipe failed");
        let size = label;
        let mut data = [0;1024];
        if num_bytes !=0 {
          let tokens: Vec<&str> = buffer.trim().split(',').collect();
          for i in 0..size as usize {
            data[i] = tokens[i].trim().parse::<u8>().expect("we expect u8");
          }
          retdata.push_back(data);
        } else {
          break;
        }
      }
    } else  {
      break;
    }
  }
  (ret,retdata)
}

*/
/*
pub fn read_pipe(piped: RawFd) -> (Vec<(u32,u32,u64,u64,u64,u32,u32,u32,u32)>, VecDeque<Vec<u8>>) {
  let f = unsafe { File::from_raw_fd(piped) };
  let mut reader = BufReader::new(f);
  let mut ret = Vec::new();
  let mut retdata = VecDeque::new();
  loop {
    let msg = PipeMsg::from_reader(&mut reader);
    if let Ok(rawmsg) = msg {
      let tid = rawmsg.tid; 
      let label = rawmsg.label;
      let direction = rawmsg.result;
      let addr = rawmsg.addr;
      let ctx = rawmsg.ctx;
      let isgep  = rawmsg.msgtype;
      let order = rawmsg.localcnt;
      let bid = rawmsg.bid;
      let sctx = rawmsg.sctx;
      ret.push((tid,label,direction,addr,ctx,order,isgep,bid,sctx));
      if isgep == 2 {
        let mut data = Vec::new();
        for _i in 0..direction as usize {
            if let Ok(cur) = reader.read_u8() {
              data.push(cur);
            } else {
              break;
            }
        } 
        if data.len() < direction as usize {
          break;
        }
        retdata.push_back(data);
      }
    } else  {
      break;
    }
  }
  (ret,retdata)
}
*/

#[cfg(test)]
mod tests {
  use super::*;
  
  #[test]
  fn test_make_pipe() {
    make_pipe()
  }

  #[test]
  fn test_read_pipe() {
    let (v,w) = read_pipe(2);
    println!("{:?}", v);
  }

}
