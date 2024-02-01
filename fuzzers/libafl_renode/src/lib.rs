
// use clap::{Arg, ArgAction, Command};
use core::{convert::TryInto, ffi::c_void, slice, time::Duration};

use std::{
    env,
    os::raw::{c_char, c_int},
    path::PathBuf,
    ffi::CString,
};
use libafl_bolts::{
    core_affinity::Cores, current_nanos, rands::StdRand, shmem::{ShMemProvider, StdShMemProvider}, tuples::{tuple_list, Merge}, AsMutSlice, AsSlice
};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{Launcher, EventConfig, SimpleEventManager},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasBytesVec, HasTargetBytes},
    monitors::MultiMonitor,
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

// Just to test
#[no_mangle]
pub unsafe extern "C" fn external_current_millis2() -> u64 {
    5000
}


#[no_mangle] // Also add edge_map pointer of something as one of the args of this func that can be populated by renode for coverage
pub extern "C" fn main_fuzzing_func(input_dir: *const c_char,
    harness_fn: extern "C" fn(*const u8, usize) -> c_int,
) {
    
    println!("Hello, entered main_fuzzing_func in libafl_renode");
    let broker_port: u16= 1337;
    let cores: Cores =  Cores::from(vec![2_usize, 3_usize]);
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        let input_dir_str = unsafe{CString::from_raw(input_dir as *mut i8).into_string().unwrap()};
        let input_dirs = &[PathBuf::from(input_dir_str)];
        let output_dir = PathBuf::from("./crashes");
        // let queue_dir = PathBuf::from("./queue");
        // Create an observation channel using the coverage map (orig)
        // let edges_observer = unsafe { HitcountsMapObserver::new(std_edges_map_observer("edges")) };
        //mod
         // Create an observation channel using the coverage map
        //  let cov_area_slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(cov_area_ptr, map_size)  };
        //  let edges: &mut [_] = cov_area_slice;
        //  let edges_observer = unsafe{StdMapObserver::new("edges", edges)};
        //  let edges_observer = unsafe { HitcountsMapObserver::new(std_edges_map_observer("edges")) };
        let edges = unsafe { &mut COV_MAP };
        let edges_observer = unsafe{StdMapObserver::new("edges", edges)};
         // Create an observation channel to keep track of the execution time
         let time_observer = TimeObserver::new("time");
          // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );
          // A feedback to choose if an input is a solution or not
          let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());
         // If not restarting, create a State from scratch
         let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });
        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
         // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
          // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |input: &BytesInput| {
            // let target = input.target_bytes();
            // let buf = target.as_slice();
            let mut buf = input.bytes().to_vec();
            let buf1 : &mut [u8]=buf.as_mut_slice();

       
            // Ensure that each byte is a valid byte (0x00 to 0xFF)
            for byte in buf.iter_mut() {
                if *byte > 0xFF {
                    *byte = 0x44;
                }
            }
            // // Convert byte slice to a string
            // let string_data = std::str::from_utf8(buf).expect("Invalid UTF-8 data");
            // // Use strip method on the string slice
            // let stripped_data = string_data.strip_suffix('\n').unwrap_or(string_data);
            //  // Replace invalid bytes with 0x44
            // let sanitized_data: Vec<u8> = stripped_data.bytes().map(|byte| if byte > 0x7F { 0x44 } else { byte }).collect();

            // // Ensure that each byte is a valid byte (0x00 to 0xFF)
            // let sanitized_data: Vec<u8> = sanitized_data.iter().map(|&byte| if byte > 0xFF { 0x44 } else { byte }).collect();

            // println!("sanitized data: {}", sanitized_data);
            harness_fn(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };
         // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
         let mut executor = InProcessExecutor::new(
                &mut harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            ).expect("Failed to create the Executor");

        println!("[*] STARTING FUZZER");
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut mgr,
                    input_dirs,
                )
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", input_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())

    };
    match Launcher::builder()
    .shmem_provider(shmem_provider)
    .configuration(EventConfig::from_name("default"))
    .monitor(monitor)
    .run_client(&mut run_client)
    .cores(&cores)
    .broker_port(broker_port)
    .stdout_file(Some("/dev/null"))
    .build()
    .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    };

}
