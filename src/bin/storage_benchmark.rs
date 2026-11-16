#[path = "../storage_benchmark.rs"]
#[allow(dead_code)]
mod storage_benchmark;

use storage_benchmark::{BenchmarkStatus, StorageBenchmarkConfig};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CliProfile {
    Advanced,
    Diagnostic,
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(directory) = args.next() else {
        eprintln!(
            "Usage: cargo run --release --bin storage_benchmark -- <existing-directory-on-target-drive> [--profile advanced|diagnostic] [--qd 1|4|8]"
        );
        std::process::exit(2);
    };
    let mut queue_depth = 1_u32;
    let mut profile = CliProfile::Advanced;
    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "--qd" => {
                let Some(value) = args.next() else {
                    eprintln!("--qd requires 1, 4, or 8");
                    std::process::exit(2);
                };
                queue_depth = match value.to_string_lossy().parse() {
                    Ok(value @ (1 | 4 | 8)) => value,
                    _ => {
                        eprintln!("--qd must be 1, 4, or 8");
                        std::process::exit(2);
                    }
                };
            }
            "--profile" => {
                let Some(value) = args.next() else {
                    eprintln!("--profile requires advanced or diagnostic");
                    std::process::exit(2);
                };
                profile = match value.to_string_lossy().as_ref() {
                    "advanced" => CliProfile::Advanced,
                    "diagnostic" => CliProfile::Diagnostic,
                    _ => {
                        eprintln!("--profile must be advanced or diagnostic");
                        std::process::exit(2);
                    }
                };
            }
            _ => {
                eprintln!("Unknown argument: {}", argument.to_string_lossy());
                std::process::exit(2);
            }
        }
    }
    if profile == CliProfile::Diagnostic {
        run_diagnostic(directory);
    } else {
        run_advanced(directory, queue_depth);
    }
}

fn run_advanced(directory: std::ffi::OsString, queue_depth: u32) {
    let mut config = StorageBenchmarkConfig::standard(directory);
    config.queue_depth = queue_depth;
    eprintln!(
        "Temporary-file benchmark: {} MiB, unbuffered/write-through, queue depth {}",
        config.test_file_size / 1024 / 1024,
        config.queue_depth
    );
    match storage_benchmark::run(&config) {
        Ok(result) => {
            println!("BLOCK | READ MB/s | WRITE MB/s | READ IOPS | WRITE IOPS");
            for run in result.runs {
                println!(
                    "{:>5} KiB | {:>9.2} | {:>10.2} | {:>9.0} | {:>10.0}",
                    run.block_size / 1024,
                    run.read.mb_per_second,
                    run.write.mb_per_second,
                    run.read.iops,
                    run.write.iops
                );
            }
            if matches!(result.status, BenchmarkStatus::Cancelled) {
                std::process::exit(130);
            }
        }
        Err(error) => {
            eprintln!("Benchmark failed: {error}");
            std::process::exit(1);
        }
    }
}

fn run_diagnostic(directory: std::ffi::OsString) {
    eprintln!("Diagnostic Summary: 512 MiB, 1 MiB blocks, QD4, 4 passes");
    match storage_benchmark::run_diagnostic_summary(directory) {
        Ok(summary) => {
            println!("PREPARATION {}", summary.preparation_method);
            println!(
                "PREPARATION ELAPSED {:.3} s",
                summary.preparation_elapsed.as_secs_f64()
            );
            for pass in &summary.raw_passes {
                println!(
                    "PASS {}  READ {:.2} MiB/s  WRITE {:.2} MiB/s  READ {:.0} IOPS  WRITE {:.0} IOPS",
                    pass.pass_number,
                    pass.run.read.mb_per_second,
                    pass.run.write.mb_per_second,
                    pass.run.read.iops,
                    pass.run.write.iops
                );
            }
            println!();
            println!("SUMMARY");
            println!("READ  {:.2} MiB/s", summary.summary_read_mib_s);
            println!("WRITE {:.2} MiB/s", summary.summary_write_mib_s);
            println!("SPREAD READ  {:.2}%", summary.read_variation_percent);
            println!("SPREAD WRITE {:.2}%", summary.write_variation_percent);
            println!("STABLE {}", if summary.stable { "YES" } else { "NO" });
        }
        Err(error) => {
            eprintln!("Diagnostic Summary failed: {error}");
            std::process::exit(1);
        }
    }
}
