mod client;
mod nts_ke;
mod packet;
mod time;

use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use client::{query, resolve, Sample};
use packet::LeapIndicator;

const USAGE: &str = "\
Usage: nts-client [SERVER] [-n SAMPLES] [-t TIMEOUT_SECS] [--nts-ke]

  SERVER   host, host:port, ip or [ipv6]:port (default: time.cloudflare.com)
  -n       number of samples, 2 s apart       (default: 4)
  -t       per-request timeout in seconds     (default: 5)
  --nts-ke only run NTS key establishment against SERVER (port 4460) and
           show what was negotiated

Measures how far this machine's clock is from SERVER using plain NTP. This does not change the system clock.";

struct Args {
    server: String,
    samples: u32,
    timeout: Duration,
    nts_ke: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        server: "time.cloudflare.com".into(),
        samples: 4,
        timeout: Duration::from_secs(5),
        nts_ke: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--nts-ke" => args.nts_ke = true,
            "-n" => {
                let v = it.next().ok_or("-n needs a value")?;
                args.samples = v.parse().ok().filter(|&n| n > 0).ok_or("-n must be >= 1")?;
            }
            "-t" => {
                let v = it.next().ok_or("-t needs a value")?;
                let secs: f64 = v
                    .parse()
                    .ok()
                    .filter(|&s| s > 0.0)
                    .ok_or("-t must be > 0")?;
                args.timeout = Duration::from_secs_f64(secs);
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => args.server = s.into(),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    if args.nts_ke {
        return run_nts_ke(&args);
    }

    let addr = match resolve(&args.server) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "Querying {} ({addr}), {} sample(s)\n",
        args.server, args.samples
    );
    println!("  #      offset        delay   stratum");

    let mut samples = Vec::new();
    for i in 1..=args.samples {
        if i > 1 {
            // Prevent spamming
            std::thread::sleep(Duration::from_secs(2));
        }
        match query(addr, args.timeout) {
            Ok(s) => {
                println!(
                    "{i:>3} {:>14} {:>12.3} ms {:>5}",
                    s.offset.to_string(),
                    s.delay.as_millis_f64(),
                    s.response.stratum
                );
                samples.push(s);
            }
            Err(e) => println!("{i:>3}   failed: {e}"),
        }
    }

    let Some(best) = samples.iter().min_by_key(|s| s.delay) else {
        eprintln!("\nerror: no valid replies");
        return ExitCode::FAILURE;
    };
    print_summary(best);
    ExitCode::SUCCESS
}

fn print_summary(s: &Sample) {
    let r = &s.response;
    let now = SystemTime::now();

    let reference = match r.stratum {
        1 => format!("{:?} (primary reference clock)", r.reference_id.ascii()),
        _ => {
            let [a, b, c, d] = r.reference_id.0;
            format!("{a}.{b}.{c}.{d} (upstream's IPv4 or a hash of its IPv6)")
        }
    };
    let leap = match r.leap {
        LeapIndicator::NoWarning => "none",
        LeapIndicator::LastMinute61 => "leap second will be inserted at end of day",
        LeapIndicator::LastMinute59 => "leap second will be deleted at end of day",
        LeapIndicator::Unsynchronized => "server unsynchronized",
    };
    let precision_ns = 2f64.powi(r.precision as i32) * 1e9;

    let offset_ms = s.offset.as_millis_f64();
    let verdict = if offset_ms.abs() < 1.0 {
        "your clock is in sync (< 1 ms)".to_string()
    } else if offset_ms > 0.0 {
        format!("your clock is {:.3} ms behind", offset_ms)
    } else {
        format!("your clock is {:.3} ms ahead", -offset_ms)
    };

    println!("\nBest sample (lowest delay):");
    println!("  Version / stratum : NTPv{} / {}", r.version, r.stratum);
    println!("  Reference ID      : {reference}");
    println!("  Leap indicator    : {leap}");
    println!(
        "  Precision         : 2^{} s (~{precision_ns:.0} ns)",
        r.precision
    );
    println!(
        "  Root delay / disp : {:.3} ms / {:.3} ms",
        r.root_delay.as_secs_f64() * 1e3,
        r.root_dispersion.as_secs_f64() * 1e3
    );
    let fmt = |t: time::NtpTimestamp| time::format_utc(t.to_system_time(now));
    println!("  T1 we sent        : {}   (our clock)", fmt(s.t1));
    println!("  T2 server got     : {}   (server clock)", fmt(s.t2));
    println!("  T3 server sent    : {}   (server clock)", fmt(s.t3));
    println!("  T4 we got         : {}   (our clock)", fmt(s.t4));
    println!("  Round-trip delay  : {:.3} ms", s.delay.as_millis_f64());
    println!("  Offset            : {}  -> {verdict}", s.offset);
    println!(
        "  Uncertainty       : ±{:.3} ms (delay / 2)",
        s.delay.as_millis_f64() / 2.0
    );
}

fn run_nts_ke(args: &Args) -> ExitCode {
    let (host, port) = match nts_ke::split_host_port(&args.server, nts_ke::DEFAULT_KE_PORT) {
        Ok(hp) => hp,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    println!(
        "NTS-KE with {host}:{port} (TLS 1.3, ALPN ntske/1)
"
    );

    let start = std::time::Instant::now();
    let keys = match nts_ke::key_exchange(&host, port, args.timeout) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let elapsed = start.elapsed();

    let aead = match keys.aead {
        nts_ke::AEAD_AES_SIV_CMAC_256 => "AEAD_AES_SIV_CMAC_256",
        _ => "unknown",
    };
    let sizes: Vec<String> = keys.cookies.iter().map(|c| c.len().to_string()).collect();

    println!(
        "  TLS               : {} / {}",
        keys.tls_version, keys.cipher_suite
    );
    println!("  Next protocol     : NTPv4");
    println!("  AEAD              : {aead} ({})", keys.aead);
    println!(
        "  NTP server        : {}",
        fmt_host_port(&keys.ntp_server, keys.ntp_port)
    );
    println!(
        "  Cookies           : {} (sizes: {} bytes)",
        keys.cookies.len(),
        sizes.join(", ")
    );
    println!(
        "  Exported keys     : c2s {} bytes, s2c {} bytes (not shown)",
        keys.c2s.len(),
        keys.s2c.len()
    );
    println!(
        "  Took              : {:.1} ms",
        elapsed.as_secs_f64() * 1e3
    );
    ExitCode::SUCCESS
}

fn fmt_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
