//! KCMVP CAVP .rsp 생성기.
//!
//! `.sam` 응답 템플릿(요청 필드 + `= ?` 답 자리)을 읽어 `?` 를 korecrypto 로
//! 계산해 채운 뒤, 같은 이름의 `.rsp` 파일로 출력한다.
//!
//! 사용법:
//!   cavp-rsp [DIR_OR_FILES...]
//!   - 인자 없음: 현재 디렉터리의 모든 *.sam 처리
//!   - 디렉터리: 그 안의 *.sam 처리
//!   - 파일들: 지정한 *.sam 처리
//!
//! 주의: NHT 는 모두 실패하며 구현 정보 없음.
//! 메일 내용:
//!   잡음원 건전성 시험에 대한 별도로 제공드릴 수 없는 점 양해바랍니다.
//!   현재 일반적인 잡음원 건전성 시험 방식은 표준 자료와 동일하오니 표준 자료를 참고하시어 구현하시기 바랍니다.
//!   잡음원 수집 방법 및 사전검증 서비스 이용 방식은 4. 엔트로피 평가 부분을 참고하시기 바랍니다.
//!   말씀해주신 LIMITED/STRICT/STREAM은 표준 용어가 아닌 사전검증 서비스에서 사용하는 용어입니다. 관련 건전성 시험 방식에 대한 가이드는 추후 업로드할 수 있도록 하겠습니다.

mod aead;
mod ccm;
mod cipher;
mod cmac;
mod ctrdrbg;
mod dh;
mod drbg;
mod ecdh;
mod ecdsa;
mod hash;
mod kdf;
mod mac;
mod nht;
mod parser;
mod pbkdf;
mod rsaes;
mod rsapss;
mod sig;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// 생성 중 오류.
#[derive(Debug)]
pub struct GenError(pub String);

impl std::fmt::Display for GenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 한 파일의 처리 결과.
pub enum GenOutcome {
    /// 성공: 채운 답 개수.
    Generated(usize),
    /// 미지원/건너뜀: 사유.
    Skipped(String),
}

/// 파일명(확장자 제거)으로 알맞은 생성기에 분배한다.
fn dispatch(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    const BLOCK_ALGOS: &[&str] = &[
        "AES-128", "AES-192", "AES-256", "ARIA-128", "ARIA-192", "ARIA-256", "SEED-128", "LEA-128",
        "LEA-192", "LEA-256", "HIGHT",
    ];
    // 블록암호: "<ALGO>_(" 로 시작.
    for algo in BLOCK_ALGOS {
        if stem.starts_with(&format!("{algo}_(")) {
            return cipher::generate(stem, items);
        }
    }
    // 해시: SHA2-/SHA3-/LSH- 로 시작.
    if stem.starts_with("SHA2-") || stem.starts_with("SHA3-") || stem.starts_with("LSH-") {
        return hash::generate(stem, items);
    }
    // DRBG.
    if stem.starts_with("CTR_DRBG") {
        return ctrdrbg::generate(stem, items);
    }
    if stem.starts_with("Hash_DRBG") || stem.starts_with("HMAC_DRBG") {
        return drbg::generate(stem, items);
    }
    // HMAC KAT (HMAC_DRBG 는 위에서 이미 처리됨).
    if stem.starts_with("HMAC_") {
        return mac::generate(stem, items);
    }
    // 전자서명 (EC-KCDSA, KCDSA). 시험유형별 지원 여부는 sig.rs 가 판단한다.
    if stem.starts_with("EC-KCDSA") || stem.starts_with("KCDSA") {
        return sig::generate(stem, items);
    }
    // GCM.
    if stem.starts_with("GCM_") {
        return aead::generate(stem, items);
    }
    // CCM.
    if stem.starts_with("CCM_") {
        return ccm::generate(stem, items);
    }
    // CMAC.
    if stem.starts_with("CMAC_") {
        return cmac::generate(stem, items);
    }
    // KBKDF.
    if stem.starts_with("KDF_") {
        return kdf::generate(stem, items);
    }
    // PBKDF2.
    if stem.starts_with("PBKDF_") {
        return pbkdf::generate(items);
    }
    // DH 키합의.
    if stem.starts_with("DH_") {
        return dh::generate(stem, items);
    }
    // ECDSA.
    if stem.starts_with("ECDSA_") {
        return ecdsa::generate(stem, items);
    }
    // ECDH 키합의.
    if stem.starts_with("ECDH_") {
        return ecdh::generate(stem, items);
    }
    // RSA-PSS (검증만).
    if stem.starts_with("RSA-PSS_") {
        return rsapss::generate(stem, items);
    }
    // RSAES-OAEP.
    if stem.starts_with("RSAES_") {
        return rsaes::generate(stem, items);
    }
    // NHT (잡음원 건전성 시험).
    if stem.starts_with("NHT_") {
        return nht::generate(stem, items);
    }
    Ok(GenOutcome::Skipped(
        "미지원 알고리즘 패밀리(후속 구현)".into(),
    ))
}

use parser::Item;

fn collect_sam(args: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let push_dir = |dir: &Path, out: &mut Vec<PathBuf>| {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("sam") {
                    out.push(p);
                }
            }
        }
    };
    if args.is_empty() {
        push_dir(Path::new("."), &mut out);
    } else {
        for a in args {
            let p = PathBuf::from(a);
            if p.is_dir() {
                push_dir(&p, &mut out);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// 한 파일 처리 결과(스레드 간 이동).
enum FileResult {
    Ok { path: String, n: usize },
    Skipped(String),
    Err(String),
}

/// 한 `.sam` 파일을 처리하고 `.rsp` 를 쓴다(스레드에서 호출).
fn process_file(sam: &Path) -> FileResult {
    let stem = sam.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let text = match std::fs::read_to_string(sam) {
        Ok(t) => t,
        Err(e) => return FileResult::Err(format!("{}: 읽기 실패: {e}", sam.display())),
    };
    let mut items = parser::parse(&text);
    match dispatch(stem, &mut items) {
        Ok(GenOutcome::Generated(n)) => {
            let rsp = sam.with_extension("rsp");
            match std::fs::write(&rsp, parser::serialize(&items)) {
                Ok(()) => FileResult::Ok {
                    path: rsp.display().to_string(),
                    n,
                },
                Err(e) => FileResult::Err(format!("{}: 쓰기 실패: {e}", rsp.display())),
            }
        }
        Ok(GenOutcome::Skipped(reason)) => FileResult::Skipped(reason),
        Err(e) => FileResult::Err(format!("{}: {e}", sam.display())),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let files = collect_sam(&args);
    if files.is_empty() {
        eprintln!("처리할 .sam 파일이 없습니다.");
        std::process::exit(1);
    }

    // 파일별 처리는 서로 독립적(각자 자기 .rsp 만 씀)이므로 CPU 수만큼
    // 스레드로 병렬화한다. 원자 카운터로 작업을 나눠 갖는다(work-stealing).
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(files.len());
    let next = AtomicUsize::new(0);
    // (원래 인덱스, 결과) — 출력 순서를 결정적으로 만들기 위해 인덱스 보관.
    let results: Mutex<Vec<(usize, FileResult)>> = Mutex::new(Vec::with_capacity(files.len()));

    std::thread::scope(|scope| {
        for _ in 0..n_threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let r = process_file(&files[i]);
                results.lock().unwrap().push((i, r));
            });
        }
    });

    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);

    let (mut ok, mut skipped, mut errored) = (0usize, 0usize, 0usize);
    let mut skip_reasons: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, r) in &results {
        match r {
            FileResult::Ok { path, n } => {
                println!("[OK ] {path} ({n} fields)");
                ok += 1;
            }
            FileResult::Skipped(reason) => {
                *skip_reasons.entry(reason.clone()).or_default() += 1;
                skipped += 1;
            }
            FileResult::Err(msg) => {
                eprintln!("[ERR] {msg}");
                errored += 1;
            }
        }
    }

    eprintln!("\n==== 요약 ====");
    eprintln!(
        "생성: {ok}, 건너뜀: {skipped}, 오류: {errored} (총 {}, 스레드 {n_threads})",
        files.len()
    );
    if !skip_reasons.is_empty() {
        eprintln!("-- 건너뛴 사유 --");
        for (r, c) in &skip_reasons {
            eprintln!("  {c:4}  {r}");
        }
    }
}
