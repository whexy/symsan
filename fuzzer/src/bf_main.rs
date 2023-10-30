use chrono::prelude::Local;
use fastgen_common::defs;
use libc::exit;
use std::{
    fs::{self, read_dir, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
};

use crate::bf_loop;
use crate::parser::init_engine;
use crate::{branches, check_dep, command, depot, executor, sync};
use crate::{cpp_interface::*, executor::Executor};
use ctrlc;
use pretty_env_logger;
use std::collections::HashMap;
use std::collections::HashSet;

pub fn bf_main(
    in_dir: &str,
    out_dir: &str,
    track_target: &str,
    pargs: Vec<String>,
    mem_limit: u64,
    time_limit: u64,
) {
    // Let's craft a vector here
    let mut fuzzed = vec![false; 0];
    pretty_env_logger::init();

    let (seeds_dir, angora_out_dir) = initialize_directories(in_dir, out_dir, false);

    let restart = in_dir == "-";
    let command_option =
        command::CommandOpt::new(track_target, pargs, &angora_out_dir, mem_limit, time_limit);
    info!("{:?}", command_option);

    check_dep::check_dep(in_dir, out_dir, &command_option);

    let depot = Arc::new(depot::Depot::new(seeds_dir, &angora_out_dir));
    info!("{:?}", depot.dirs);

    let global_branches = Arc::new(branches::GlobalBranches::new());
    let branch_gencount = Arc::new(RwLock::new(HashMap::<(u64, u32, u32, u64), u32>::new()));
    let branch_fliplist = Arc::new(RwLock::new(HashSet::<(u64, u32, u32, u64)>::new()));
    let running = Arc::new(AtomicBool::new(true));
    let forklock = Arc::new(Mutex::new(0));
    set_sigint_handler(running.clone());

    let mut executor = executor::Executor::new(
        command_option.specify(0),
        global_branches.clone(),
        depot.clone(),
        0,     //shmid is zero
        false, //not grading
        forklock.clone(),
    );

    sync::sync_depot(&mut executor, running.clone(), &depot.dirs.seeds_dir);

    if depot.empty() {
        error!(
            "Please ensure that seed directory - {:?} has ang file",
            depot.dirs.seeds_dir
        );
    }

    unsafe {
        init_core();
    }
    init_engine();

    let mut id = 0;
    // This is the big while loop for fuzzing!!!
    loop {
        bf_wait(&mut executor);

        // use the latest input
        let mut max_id = depot.get_num_inputs() - 1;
        if max_id > fuzzed.len() {
            fuzzed.resize(max_id + 1, false);
        }
        while fuzzed[max_id] && max_id > 0 {
            max_id -= 1;
        }
        fuzzed[max_id] = true;
        id = max_id as u32;

        let solutions = {
            let r = running.clone();
            let d = depot.clone();
            let b = global_branches.clone();
            let cmd = command_option.specify(2);
            let bg = branch_gencount.clone();
            let blist = branch_fliplist.clone();
            let fk = forklock.clone();
            bf_loop::fuzz_loop(r, cmd, d, b, bg, blist, restart, fk, id)
        };
        {
            let r = running.clone();
            let d = depot.clone();
            let b = global_branches.clone();
            let cmd = command_option.specify(2);
            let bg = branch_gencount.clone();
            let blist = branch_fliplist.clone();
            let fk = forklock.clone();
            bf_loop::grading_loop(r, cmd, d, b, bg, blist, fk, solutions);
        }
    }
}

fn initialize_directories(in_dir: &str, out_dir: &str, sync_afl: bool) -> (PathBuf, PathBuf) {
    let angora_out_dir = if sync_afl {
        gen_path_afl(out_dir)
    } else {
        PathBuf::from(out_dir)
    };

    let restart = in_dir == "-";
    if !restart {
        fs::create_dir(&angora_out_dir).expect("Output directory has existed!");
    }

    let workdir = PathBuf::from("angora");

    let out_dir = &angora_out_dir;
    let seeds_dir = if restart {
        let orig_out_dir = workdir.with_extension(Local::now().to_rfc3339());
        println!("orig out dir is {:?}", orig_out_dir);
        fs::rename(&out_dir, orig_out_dir.clone()).unwrap();
        fs::create_dir(&out_dir).unwrap();
        PathBuf::from(orig_out_dir).join(defs::INPUTS_DIR)
    } else {
        PathBuf::from(in_dir)
    };

    (seeds_dir, angora_out_dir)
}

fn gen_path_afl(out_dir: &str) -> PathBuf {
    let base_path = PathBuf::from(out_dir);
    let create_dir_result = fs::create_dir(&base_path);
    if create_dir_result.is_err() {
        warn!("dir has existed. {:?}", base_path);
    }
    base_path.join(defs::ANGORA_DIR_NAME)
}

fn set_sigint_handler(r: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        warn!("Ending Fuzzing.");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting SIGINT handler!");
}

static mut GO_COUNT: u32 = 0;

fn bf_wait(executor: &mut Executor) {
    let pipe_path = "/dev/shm/bf-symsan";

    unsafe {
        if GO_COUNT > 0 {
            GO_COUNT -= 1;
            return;
        }
    }

    // Write Stage, write to pipe "ready" or "new".
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open(pipe_path)
            .expect("open pipe failed");
        file.write_all(b"ready").expect("write pipe failed");
    }

    // Read Stage, read from the pipe
    loop {
        let mut buf = Vec::new();
        {
            let mut file = OpenOptions::new()
                .read(true)
                .open(pipe_path)
                .expect("open pipe failed");
            file.read_to_end(buf.as_mut()).expect("read pipe failed");
        }
        let raw_string = String::from_utf8_lossy(&buf);
        let message = raw_string.trim();

        match message {
            "stop" => unsafe {
                exit(0);
            },
            "sync" => {
                bf_sync(executor);
                {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .open(pipe_path)
                        .expect("open pipe failed");
                    file.write_all(b"synced").expect("write pipe failed");
                }
            }
            "go" => {
                break;
            }
            msg if msg.starts_with("go:") => {
                let parts: Vec<_> = msg.split(":").collect();
                if let Ok(count) = parts[1].parse::<u32>() {
                    unsafe {
                        GO_COUNT = count;
                    }
                    break;
                } else {
                    unsafe {
                        exit(1);
                    }
                }
            }
            _ => unsafe {
                exit(1);
            },
        }
    }
}

fn bf_sync(executor: &mut Executor) {
    let sync_dir = Path::new("/dev/shm/bf-sync-seeds");
    let entries = read_dir(sync_dir).expect("Error opening the sync dir");

    for entry in entries {
        let path = entry.unwrap().path();
        let metadata = fs::metadata(&path).unwrap();

        if metadata.is_file() && metadata.len() > 0 {
            let mut file = File::open(&path).unwrap();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            executor.run_norun(&content);
        }
    }
}
