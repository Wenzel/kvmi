use std::fs::File;
use std::io::Write;
use std::path::Path;

use kvmi::constants::PAGE_SIZE;
use kvmi::{create_kvmi, KVMIntrospectable, SocketType};

use clap::{App, Arg, ArgMatches};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, trace};

fn parse_args() -> ArgMatches<'static> {
    App::new(file!())
        .version("0.1")
        .author("Mathieu Tarral")
        .about("Dumps VM physical memory")
        .arg(Arg::with_name("vm_name").index(1).required(true))
        .arg(
            Arg::with_name("unix_socket")
                .short("u")
                .takes_value(true)
                .help("KVMi UNIX socket"),
        )
        .arg(
            Arg::with_name("vsock_port")
                .short("v")
                .takes_value(true)
                .help("KVMi vSock port"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .takes_value(true)
                .help("Output path"),
        )
        .get_matches()
}

fn main() {
    env_logger::init();

    // handle args
    let matches = parse_args();
    let domain_name = matches
        .value_of("vm_name")
        .expect("The VM name is required");

    // either one of unix or vsock socket
    let unix_socket = matches
        .value_of("unix_socket")
        .map(|s| SocketType::UnixSocket(s.to_string()));
    let vsock_socket = matches.value_of("vsock_port").map(|s| {
        SocketType::VSock(s.parse::<u32>().expect(&*format!(
            "Failed to convert command line value \"{}\" to vSock port integer",
            s
        )))
    });
    let kvmi_sock_type = unix_socket.unwrap_or_else(|| {
        vsock_socket.expect("One of UNIX or vSock connection method must be specified.")
    });

    let dump_path = Path::new(
        matches
            .value_of("output")
            .map_or(&*format!("{}.dump", domain_name), |v| v),
    )
    .to_path_buf();
    let mut dump_file = File::create(&dump_path).expect("Fail to open dump file");
    // canonicalize now that the file exists
    dump_path.canonicalize().unwrap();

    // create KVMi and init
    let mut kvmi = create_kvmi();

    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(200);
    spinner.set_message("Initializing KVMi...");
    kvmi.init(kvmi_sock_type)
        .expect("Failed to initialize KVMi");
    spinner.finish_and_clear();

    // ensure paused before dumping the RAM
    println!("Pausing the VM");
    kvmi.pause().expect("Failed to pause the VM");

    let max_addr = kvmi
        .get_maximum_paddr()
        .expect("Failed to retrieve the highest physical address");
    println!(
        "Dumping {} memory to {} until {:#X}",
        domain_name,
        dump_path.file_name().unwrap().to_str().unwrap(),
        max_addr
    );
    let bar = ProgressBar::new(max_addr);
    bar.set_style(ProgressStyle::default_bar().template(
        "{prefix} {wide_bar} {bytes_per_sec} • {bytes}/{total_bytes} • {percent}% • {elapsed}",
    ));
    // redraw every 0.1% change, otherwise the redraw becomes the bottleneck
    bar.set_draw_delta(max_addr / 1000);

    // dump memory, frame by frame
    for cur_paddr in (0..max_addr).step_by(PAGE_SIZE) {
        trace!(
            "reading {:#X} bytes of memory at {:#X}",
            PAGE_SIZE,
            cur_paddr
        );
        // reset buffer each loop
        let mut buffer: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        kvmi.read_physical(cur_paddr, &mut buffer)
            .unwrap_or_else(|_| debug!("failed to read memory at {:#X}", cur_paddr));
        dump_file
            .write_all(&buffer)
            .expect("failed to write to file");
        // update bar
        bar.set_prefix(&*format!("{:#X}", cur_paddr));
        bar.inc(PAGE_SIZE as u64);
    }
    bar.finish();
    println!(
        "Finished dumping physical memory at {}",
        dump_path.display()
    );

    println!("Resuming the VM");
    kvmi.resume().expect("Failed to resume VM");
}
