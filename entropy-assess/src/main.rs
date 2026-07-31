//! KCMVP 엔트로피 평가용 잡음원 샘플 파일 생성기.
//!
//! 사용법:
//!   entropy-assess collect [--num N] [--label OS-ARCH] [출력파일]
//!       실제 KCMVP 모듈의 잡음원에서 N(기본 250000)개 샘플을 수집해
//!       평가 파일을 만든다. (반드시 `--features kcmvp` 로 빌드해야 실제
//!       모듈 경로로 수집된다.)
//!
//!   entropy-assess format [--bits B] [--num N] --input RAW [출력파일]
//!       이미 수집된 8 비트 원시 샘플 바이너리(RAW, 샘플당 1 바이트)를 읽어
//!       평가 파일 형식으로 변환한다. (UEFI 등 파일 시스템이 없는 타깃에서
//!       시리얼로 덤프한 원시 바이트를 호스트에서 포맷할 때 사용.)
//!
//! 출력파일을 생략하면 `entropy-<label>.txt` 로 저장한다.

use std::io::{Read, Write};
use std::process::ExitCode;

use entropy_assess::{format_sample_file, NUM_SAMPLES};

fn usage() -> ExitCode {
    eprintln!(
        "Usage:\n  \
         entropy-assess collect [--num N] [--label OS-ARCH] [OUTFILE]\n  \
         entropy-assess format [--bits B] --input RAW [OUTFILE]"
    );
    ExitCode::from(2)
}

fn default_label() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return usage();
    }
    match args[1].as_str() {
        "collect" => cmd_collect(&args[2..]),
        "format" => cmd_format(&args[2..]),
        _ => usage(),
    }
}

/// `--key value` 형태의 옵션과 위치 인자를 분리한다.
fn parse_opts(args: &[String]) -> (std::collections::HashMap<String, String>, Vec<String>) {
    let mut opts = std::collections::HashMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            let val = args.get(i + 1).cloned().unwrap_or_default();
            opts.insert(key.to_string(), val);
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    (opts, positional)
}

fn write_output(path: &str, contents: &str) -> ExitCode {
    match std::fs::File::create(path).and_then(|mut f| f.write_all(contents.as_bytes())) {
        Ok(()) => {
            eprintln!("[entropy-assess] wrote {path} ({} bytes)", contents.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[entropy-assess] failed to write {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_collect(args: &[String]) -> ExitCode {
    let (opts, positional) = parse_opts(args);
    let num: usize = match opts.get("num") {
        Some(v) => match v.parse() {
            Ok(n) => n,
            Err(_) => return usage(),
        },
        None => NUM_SAMPLES,
    };
    let label = opts.get("label").cloned().unwrap_or_else(default_label);
    let out = positional
        .first()
        .cloned()
        .unwrap_or_else(|| format!("entropy-{label}.txt"));

    if !korecrypto::kcmvp::enabled() {
        eprintln!(
            "[entropy-assess] WARNING: module is NOT in KCMVP mode; \
             build with --features kcmvp to collect through the validated path."
        );
    }

    let bits = korecrypto::kcmvp::entropy_noise_sample_bits();
    if bits == 0 {
        eprintln!("[entropy-assess] no jitter noise source available on this platform");
        return ExitCode::FAILURE;
    }

    eprintln!("[entropy-assess] collecting {num} raw noise-source samples ({bits}-bit) ...");
    let mut samples = vec![0u8; num];
    if !korecrypto::kcmvp::collect_raw_noise_samples(&mut samples) {
        eprintln!("[entropy-assess] sample collection failed");
        return ExitCode::FAILURE;
    }

    write_output(&out, &format_sample_file(bits, &samples))
}

fn cmd_format(args: &[String]) -> ExitCode {
    let (opts, positional) = parse_opts(args);
    let bits: u32 = opts.get("bits").and_then(|v| v.parse().ok()).unwrap_or(8);
    let input = match opts.get("input") {
        Some(p) => p.clone(),
        None => return usage(),
    };

    let mut raw = Vec::new();
    let read_res = if input == "-" {
        std::io::stdin().read_to_end(&mut raw)
    } else {
        std::fs::File::open(&input).and_then(|mut f| f.read_to_end(&mut raw))
    };
    if let Err(e) = read_res {
        eprintln!("[entropy-assess] failed to read {input}: {e}");
        return ExitCode::FAILURE;
    }

    let label = opts.get("label").cloned().unwrap_or_else(default_label);
    let out = positional
        .first()
        .cloned()
        .unwrap_or_else(|| format!("entropy-{label}.txt"));

    write_output(&out, &format_sample_file(bits, &raw))
}
