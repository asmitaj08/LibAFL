use std::fs::OpenOptions;
use std::io::Write;
// use clap::{Arg, ArgAction, Command};
use core::{convert::TryInto, ffi::c_void, slice, time::Duration};
use serde::{de::DeserializeOwned, Serialize};
use libafl::stages::RetryCountRestartHelper;
use libafl_bolts::serdeany::RegistryBuilder;
use std::sync::{Mutex, atomic::{AtomicPtr, Ordering}};
use lazy_static::lazy_static;
use std::ptr;
// use log::{debug, error, log_enabled, info, Level};

use std::{
    env,
    os::raw::{c_char, c_int},
    path::PathBuf,
    ffi::CString,
    iter,
};
use libafl_bolts::{
    core_affinity::Cores, current_nanos, rands::StdRand, shmem::{ShMemProvider, StdShMemProvider}, tuples::{tuple_list, Merge}, AsSlice,
    // shmem::{ShMem, ShMemProvider, UnixShMemProvider},
};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{Launcher, EventConfig, SimpleEventManager, SendExiting, ShutdownSignalData},
    // executors::{inprocess::InProcessExecutor, ExitKind},
    executors::{ExitKind, InProcessExecutor},
    feedback_or,feedback_or_fast, feedback_and,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{RandBytesGenerator,RandPrintablesGenerator},
    inputs::{BytesInput, HasTargetBytes, MultipartInput},
    // monitors::MultiMonitor, monitors::SimpleMonitor,
    monitors::{MultiMonitor,SimpleMonitor},
    mutators::{havoc_mutations::havoc_mutations, scheduled::{tokens_mutations, StdScheduledMutator}},

    // mutators::{
    //     havoc_mutations::havoc_mutations, scheduled::{tokens_mutations, StdScheduledMutator},
    //     token_mutations::{I2SRandReplace, Tokens},
    // },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, StdWeightedScheduler,
        IndexesLenTimeMinimizerScheduler, QueueScheduler
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, GeneralizationStage,
        StdMutationalStage, TracingStage,
    },
    state::{StdState, HasCorpus},
    Error,
    Evaluator,
};

pub use libafl_targets::{EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_ALLOCATED_SIZE, EDGES_MAP_DEFAULT_SIZE,CmpLogObserver, MAX_EDGES_FOUND};

// use libafl_targets::{
//     CmpLogObserver, std_edges_map_observer, EDGES_MAP_PTR,
//     MAX_EDGES_NUM,EDGES_MAP_SIZE,
// };

const MAP_SIZE: usize =  64 * 1024; //2621440 ; // 8 * 1024; // 0x280000 (i.e. 2621440) for EDGES_MAP_ALLOCATED_SIZE 
// static mut PREV_LOC: u64 = 0; 
// pub use libafl_targets::{EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_ALLOCATED_SIZE};

#[no_mangle] // coverage map
static mut COV_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

#[no_mangle] 
pub extern "C" fn get_cov_map_ptr() -> *mut u8 { 

    unsafe{
        // EDGES_MAP_PTR
        // COV_MAP.as_mut_ptr()
        let ptr = COV_MAP.as_mut_ptr();
        println!("*****Coverage Map Pointer Address - Libafl: {:?}", ptr);
        // println!("******Coverage Map Pointer Address (pointer format): {:p}", ptr);
        ptr

    }

} 

// Use lazy_static to initialize a static Mutex-wrapped array (coverage map)
// lazy_static! {
//     pub static ref COV_MAP: Mutex<[u8; MAP_SIZE]> = Mutex::new([0; MAP_SIZE]);
// }

// Function to get the pointer to COV_MAP 
// #[no_mangle] 
// pub extern "C" fn get_cov_map_ptr() -> *mut u8 { 

//    // unsafe{
//         // EDGES_MAP_PTR
//         // COV_MAP.as_mut_ptr()
//         // let ptr = COV_MAP.as_mut_ptr();
//         // Locking access to the coverage map
//         let mut cov_map = COV_MAP.lock().unwrap();
//         let cov_map_ptr =  cov_map.as_mut_ptr();
//         println!("*****Coverage Map Pointer Address - Libafl: {:?}", cov_map_ptr);
//         // println!("******Coverage Map Pointer Address (pointer format): {:p}", ptr);
//         cov_map_ptr

//   //  }

// } 

const INPUT_SIZE_MAX: usize = 1024;

#[no_mangle] 
static mut INPUT_DATA: [u8; INPUT_SIZE_MAX] = [0; INPUT_SIZE_MAX];
// static ref INPUT_DATA: Mutex<[u8; MAP_SIZE]> = Mutex::new([0; INPUT_SIZE]);
// static mut INPUT_DATA: Vec<u8> = Vec::new();

#[no_mangle] 
pub extern "C" fn get_input_ptr() -> *mut u8 { 
    unsafe{
        let ptr = INPUT_DATA.as_mut_ptr();
        // let in_data = INPUT_DATA.lock().unwrap();
        // let ptr = in_data.as_mut_ptr();
        println!("*****INPUT_DATA Pointer Address - Libafl: {:?}", ptr);
        ptr

    }
} 

#[no_mangle] 
static mut INPUT_SIZE: usize = 0;

#[no_mangle] 
pub extern "C" fn get_input_size_ptr() -> *mut usize { 
    unsafe{
        let ptr : *mut usize = &mut INPUT_SIZE;
        println!("*****INPUT_SIZE Pointer Address - Libafl: {:?}", ptr);
        // println!("******Coverage Map Pointer Address (pointer format): {:p}", ptr);
        ptr

    }
} 

// lazy_static! {
//     pub static ref UART_IN: Mutex<[u8; INPUT_SIZE]> = Mutex::new([0; INPUT_SIZE]);
//     // pub static ref UART_IN_SIZE: Mutex<usize> = Mutex::new(0); // Mutex to store the actual size of data
// }

// #[no_mangle] 
// pub extern  "C" fn get_uart_input_ptr() -> *mut u8{
//     let mut uart_in = UART_IN.lock().unwrap();
//     let uart_in_ptr =  uart_in.as_mut_ptr();
//     println!("*****UART IN Pointer Address - Libafl: {:?}", uart_in_ptr);
//     uart_in_ptr
    
// }

// #[no_mangle] 
// pub extern  "C" fn get_uart_input_size() -> usize{
//     let uart_input_size = UART_IN_SIZE.lock().unwrap(); // Lock access to size
//     // println!("*****UART INPUT SIZE  - Libafl: {:?}", *uart_input_size);
//     *uart_input_size
    
// }

// lazy_static! {
//     pub static ref UART_PTR_SH: Mutex<Vec<u8>> = Mutex::new(Vec::new()); // earlier I was trying to make it work by initilaizing without size being known beforehand, but it will crash 
// }

// #[no_mangle] // older version with unknown INPUT size and the pointer always kept getting updated as per buf, but it crashes
// pub extern  "C" fn update_uart_input_data(out_size: &mut usize) -> *const u8{
//     let uart_buff = UART_PTR_SH.lock().unwrap();
//     *out_size = uart_buff.len();
//     uart_buff.as_ptr()
    
// }
 


// Just to test
#[no_mangle]
pub unsafe extern "C" fn external_current_millis2() -> u64 {
    5000
}


// fn count_non_zero_elements_covMap() -> usize {
//     let mut count = 0;
//     unsafe {
//         for &value in COV_MAP.iter() {
//             if value != 0 {
//                 count += 1;
//             }
//         }
//     }
//     count
// }


#[no_mangle] 
pub extern "C" fn main_fuzzing_func(input_dir: *const c_char,
    harness_fn: extern "C" fn()->u8,
) {
    env_logger::init();
    println!("Hello, entered main_fuzzing_func in libafl_renode");

    println!("Setting up Harness");
    let mut harness = |input: &BytesInput| {
        
            let target = input.target_bytes();
            let buf = target.as_slice();
            if !buf.is_empty() {
                let len = std::cmp::min(buf.len(), INPUT_SIZE_MAX);
                unsafe{
                    INPUT_DATA[..len].copy_from_slice(&buf[..len]);
                    INPUT_SIZE = len;
                }
            }
        
        // let non_zero_count_covMap = count_non_zero_elements_covMap();
        // println!("Number of non-zero elements in COV_MAP: {}, Coverage Map Pointer Address: {:?}", non_zero_count_covMap, unsafe{COV_MAP.as_mut_ptr()});
        let ret : u8 = harness_fn(); 
        // ExitKind::Ok 
        // let ret = harness_fn(buf.as_ptr());
        // let ret1=0;
        // //println!("#######Harness func return val {}", ret);
        match ret {
            0 => ExitKind::Ok,
            2 => ExitKind::Timeout,
            _=> ExitKind::Crash,
        }
    };
    println!("Harness setup done");
    // println!("Done setting up dirs");
   let edges = unsafe { &mut COV_MAP }; //orig
    // // let edges = unsafe { &mut EDGES_MAP };
    // let edges_observer = unsafe{StdMapObserver::new("edges", edges)}; //orig

    // #[allow(static_mut_refs)] // only a problem on nightly
    // let edges_observer = unsafe {
    //     HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
    //         "edges",
    //         COV_MAP.as_mut_ptr(),
    //         MAX_EDGES_FOUND,
    //     ))
    //     .track_indices()
    // };

    #[allow(static_mut_refs)] // only a problem on nightly
    let edges_observer = unsafe {
        HitcountsMapObserver::new(unsafe{StdMapObserver::new("edges", edges)})
        .track_indices()
    };

    // let mut cov_map = COV_MAP.lock().unwrap();  // Locking access to COV_MAP
    // let edges = &mut *cov_map;  // Derefencing the MutexGuard to get access to the array

    // let edges_observer = unsafe { StdMapObserver::new("edges", edges) };

    // let mut observers = tuple_list!(edges_observer);

    // // The unix shmem provider supported by AFL++ for shared memory
    // let mut shmem_provider = UnixShMemProvider::new().unwrap();
    // // The coverage map shared between observer and executor
    // let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let shmem_buf = shmem.as_mut_slice();

    // let edges_observer = unsafe{StdMapObserver::new("shared_mem", shmem_buf)};

    // let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
   
    let time_observer = TimeObserver::new("time");
    
    // let mut feedback = MaxMapFeedback::new(&edges_observer); // working
    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&map_feedback);
   
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );


    let mut objective = feedback_or_fast!(
        CrashFeedback::new(),   
        TimeoutFeedback::new());

    // let mut objective = CrashFeedback::new();   // make it timeout objective??

   
    println!("[*] creating state");
    // If not restarting, create a State from scratch
    let mut state = StdState::new
    (
        // RNG
        StdRand::with_seed(10),
        // Corpus that will be evolved, we keep it in memory for performance
        // InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./queue_dir")).unwrap(),
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

    // let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The Monitor trait define how the fuzzer stats are displayed to the user
    // #[cfg(not(feature = "tui"))]
    // println!("[*] feature not tui, proceeding with SimpleMonitor");
    // let mon = SimpleMonitor::new(|s| println!("{s}"));
    // #[cfg(feature = "tui")]
    // let mon = TuiMonitor::builder()
    //     .title("Renode Fuzzer")
    //     .enhanced_graphics(false)
    //     .build();

    let mon = MultiMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);
    
    // let scheduler = QueueScheduler::new();

   

    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    // let mutator = StdScheduledMutator::new(havoc_mutations());
    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    let mut stages = tuple_list!(calibration, power);

     // A minimization+queue policy to get testcasess from the corpus
     let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );

     // A fuzzer with feedbacks and a corpus scheduler
     let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
     println!("[*] fuzzer, scheduler setup done");
    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    // let mut executor = InProcessExecutor::new(
        let mut executor = InProcessExecutor::with_timeout(
            &mut harness,
            // tuple_list!(edges_observer),
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            Duration::new(10, 0), // 10 seconds timeout
    ).expect("Failed to create the Executor");
    println!("[*] executor setup done");
     // Generator of printable bytearrays of max size 32
    // let mut generator = RandBytesGenerator::new(8);

    println!("Calling to load initial inputs");

    //  // Generate 8 initial inputs - bytesInput
    //  fuzzer
    //  .evaluate_input(
    //      &mut state,
    //      &mut executor,
    //      &mut mgr,
    //      &BytesInput::new(vec![b'a']),
    //  )
    //  .unwrap();

     // Generator of printable bytearrays of max size 32
    //  let mut generator = RandBytesGenerator::new(1);

    //  // Generate 8 initial inputs
    //  state
    //      .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 2)
    //      .expect("Failed to generate the initial corpus");

    //commented this state.load_inputs for multipart
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
    
    println!("[*] fuzz_loop");
       
    // fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    // .expect("Error in the fuzzing loop");

    match fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr) {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
    
    // let edge_count = count_covered_edges(unsafe { &COV_MAP });
    // println!("[*] fuzz_loop done, edge covergae : {}", edge_count);

}
