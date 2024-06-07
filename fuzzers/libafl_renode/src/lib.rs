use std::fs::OpenOptions;
use std::io::Write;
// use clap::{Arg, ArgAction, Command};
use core::{convert::TryInto, ffi::c_void, slice, time::Duration};
// use log::{debug, error, log_enabled, info, Level};

use std::{
    env,
    os::raw::{c_char, c_int},
    path::PathBuf,
    ffi::CString,
};
use libafl_bolts::{
    core_affinity::Cores, current_nanos, rands::StdRand, shmem::{ShMemProvider, StdShMemProvider}, tuples::{tuple_list, Merge}, AsMutSlice, AsSlice,
    // shmem::{ShMem, ShMemProvider, UnixShMemProvider},
};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{Launcher, EventConfig, SimpleEventManager},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{RandBytesGenerator,RandPrintablesGenerator},
    inputs::{BytesInput, HasBytesVec, HasTargetBytes},
    monitors::MultiMonitor, monitors::SimpleMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        // token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{HitcountsMapObserver, TimeObserver, StdMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{StdMutationalStage, TracingStage},
    state::{StdState, HasCorpus},
    Error,
};
use libafl_targets::{
    CmpLogObserver, std_edges_map_observer, EDGES_MAP_PTR,
    MAX_EDGES_NUM,EDGES_MAP_SIZE,
};

const MAP_SIZE: usize = 8 * 1024;
static mut PREV_LOC: u64 = 0; 
// pub use libafl_targets::{EDGES_MAP_PTR, EDGES_MAP_SIZE};

#[no_mangle] // coverage map
pub static mut COV_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// Function to get the pointer to COV_MAP 
#[no_mangle] 
pub extern "C" fn get_cov_map_ptr() -> *mut u8 { 

    unsafe{
        COV_MAP.as_mut_ptr()
    }

} 

// Function to update COV_MAP
// #[no_mangle]
// pub extern  "C" fn update_cov_map(pc: u64){
//     unsafe{
//         let hash = (pc ^ PREV_LOC) & (MAP_SIZE as u64 - 1);
//         COV_MAP[hash as usize] += 1; 
//         PREV_LOC = pc >> 1; 
//         let cov_val = COV_MAP[hash as usize];
//         let mut logfile = OpenOptions::new()
//             .create(true)
//             .append(true)
//             .open("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/log_libafl.txt")
//             .expect("Failed to open or create the log file");
         
//         // Write the message to the file
//         writeln!(logfile, "update cov map: hash : {hash}, prev_loc : {PREV_LOC},cov : {cov_val}").expect("Failed to write to the log file");
//     }

//     }
 


// Just to test
#[no_mangle]
pub unsafe extern "C" fn external_current_millis2() -> u64 {
    5000
}


#[no_mangle] // Also add edge_map pointer of something as one of the args of this func that can be populated by renode for coverage
pub extern "C" fn main_fuzzing_func(input_dir: *const c_char,
    harness_fn: extern "C" fn(*const u8),
) {
    env_logger::init();
    println!("Hello, entered main_fuzzing_func in libafl_renode");

    println!("Setting up Harness");
    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
         // Open the file in append mode or create it if it doesn't exist
        // let mut logfile = OpenOptions::new()
        //     .create(true)
        //     .append(true)
        //     .open("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/log_libafl.txt")
        //     .expect("Failed to open or create the log file");

        // // Write the message to the file
        // unsafe{writeln!(logfile, "In libafl harness, cov map : {:?}", COV_MAP).expect("Failed to write to the log file")};
        
        let target = input.target_bytes();
        let buf = target.as_slice();
        // let mut buf = input.bytes().to_vec();
        //let buf1 : &mut [u8]=buf.as_mut_slice();
        harness_fn(buf.as_ptr());
        ExitKind::Ok  
        
        // let ret = harness_fn(buf.as_ptr(), buf.len());
        // let ret = harness_fn(buf.as_ptr());
        // //println!("#######Harness func return val {}", ret);
        // match ret {
        //     0 => ExitKind::Ok,
        //     // 2 => ExitKind::Timeout,
        //     _=> ExitKind::Crash,
        // }
    };
    println!("Harness setup done");
    // println!("Done setting up dirs");
    let edges = unsafe { &mut COV_MAP };
    let edges_observer = unsafe{StdMapObserver::new("edges", edges)};
    // // The unix shmem provider supported by AFL++ for shared memory
    // let mut shmem_provider = UnixShMemProvider::new().unwrap();
    // // The coverage map shared between observer and executor
    // let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let shmem_buf = shmem.as_mut_slice();

    // let edges_observer = unsafe{StdMapObserver::new("shared_mem", shmem_buf)};

    // let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
    let mut feedback = MaxMapFeedback::new(&edges_observer);

    let mut objective = CrashFeedback::new();
   
    println!("[*] creating state");
    // If not restarting, create a State from scratch
    let mut state = StdState::new
    (
        // RNG
        StdRand::with_seed(10),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    ).unwrap();
    // ){
    //     Ok(state) => state,
    //     Err(err) => {
    //     // If the construction fails, display the error and stop the program
    //     eprintln!("############Error occurred while creating StdState: {:?}", err);
    //     // Optionally, you can choose to panic here to stop the program immediately
    //     // panic!("Error occurred while creating StdState: {:?}", err);
    //     return; // Or use another way to exit the function or block
    //     }
    // };

    // .unwrap();
    println!("[*] State creation done");

    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);
    
    let scheduler = QueueScheduler::new();
     // A fuzzer with feedbacks and a corpus scheduler
     let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
     println!("[*] fuzzer, scheduler setup done");
    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
    ).expect("Failed to create the Executor");
    println!("[*] executor setup done");
     // Generator of printable bytearrays of max size 32
    // let mut generator = RandBytesGenerator::new(8);

    println!("Calling to load initial inputs");
     // Generator of printable bytearrays of max size 32
    //  let mut generator = RandBytesGenerator::new(1);

    //  // Generate 8 initial inputs
    //  state
    //      .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 2)
    //      .expect("Failed to generate the initial corpus");

    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir/")]).unwrap();
    // match state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/input_dir/")]){
    //     Ok(()) => {
    //         // If the function call succeeds, continue with the rest of the program
    //     },
    //     Err(err) => {
    //         // If the function call fails, display the error and stop the program
    //         eprintln!("Error occurred: {:?}", err);
    //         // Optionally, you can choose to panic here to stop the program immediately
    //         // panic!("Error occurred: {:?}", err);
    //     }
    // }
    println!("Loaded initial inputs");
    
    println!("[*] STARTING FUZZER");
    // let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    println!("[*] fuzz_loop");
       
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    .expect("Error in the fuzzing loop");

}
