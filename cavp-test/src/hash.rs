//! 해시함수 CAVP 생성기 (LMT/SMT 단문·장문, MCT Monte-Carlo).
//!
//! SHA-2, SHA-3, LSH 를 지원한다. MCT 는 알고리즘 계열에 따라 다르다:
//! - SHA-2/LSH(Merkle-Damgård): MD[i]=Hash(MD[i-3]||MD[i-2]||MD[i-1]) (SHAVS 방식)
//! - SHA-3(스펀지): MD[i]=Hash(MD[i-1]) (SHA3VS 방식)

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::hash::{hash, MessageDigest};

/// 해시 → (다이제스트, 입력 블록 크기 바이트). 블록 크기는 SHA-3 의 경우
/// 스펀지 rate, LSH 는 메시지 블록(LSH-256=128B, LSH-512=256B).
fn lookup(algo: &str) -> Option<(MessageDigest, usize)> {
    Some(match algo {
        "SHA2-224" => (MessageDigest::sha224(), 64),
        "SHA2-256" => (MessageDigest::sha256(), 64),
        "SHA2-384" => (MessageDigest::sha384(), 128),
        "SHA2-512" => (MessageDigest::sha512(), 128),
        "SHA3-224" => (MessageDigest::sha3_224(), 144),
        "SHA3-256" => (MessageDigest::sha3_256(), 136),
        "SHA3-384" => (MessageDigest::sha3_384(), 104),
        "SHA3-512" => (MessageDigest::sha3_512(), 72),
        "LSH-256-224" => (MessageDigest::lsh256_224(), 128),
        "LSH-256-256" => (MessageDigest::lsh256_256(), 128),
        "LSH-512-224" => (MessageDigest::lsh512_224(), 256),
        "LSH-512-256" => (MessageDigest::lsh512_256(), 256),
        "LSH-512-384" => (MessageDigest::lsh512_384(), 256),
        "LSH-512-512" => (MessageDigest::lsh512_512(), 256),
        _ => return None,
    })
}

fn md(d: MessageDigest, data: &[u8]) -> Vec<u8> {
    hash(d, data).expect("hash").to_vec()
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s).map_err(|e| GenError(format!("hex: {e}")))
}

/// 파일명 "SHA2-256_(Byte)_LMT" → ("SHA2-256","LMT").
fn parse_name(stem: &str) -> Option<(String, String)> {
    // <ALGO>_(Byte)_<TYPE>
    let close = stem.rfind(')')?;
    let open = stem.find('(')?;
    let algo = stem[..open].trim_end_matches('_').to_string();
    let ttype = stem[close + 1..].trim_start_matches('_').to_string();
    Some((algo, ttype))
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (algo, ttype) = match parse_name(stem) {
        Some(t) => t,
        None => return Ok(GenOutcome::Skipped("파일명 파싱 실패".into())),
    };
    let (digest, block) = match lookup(&algo) {
        Some(x) => x,
        None => return Ok(GenOutcome::Skipped(format!("미지원 해시: {algo}"))),
    };

    match ttype.as_str() {
        "LMT" | "SMT" => msg_test(digest, items),
        "MCT" => mct(digest, block, items),
        other => Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
    }
}

/// 장문/단문 시험: 각 레코드의 Msg(Len 비트)를 해시.
fn msg_test(digest: MessageDigest, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let len_bits: usize = match get(items, rec, "Len") {
            Some(l) => l.trim().parse().map_err(|_| GenError("Len 파싱".into()))?,
            None => continue,
        };
        let msg_hex = get(items, rec, "Msg").unwrap_or("").to_string();
        let mut msg = hx(&msg_hex)?;
        msg.truncate(len_bits / 8); // Len=0 이면 빈 입력
        let digest_hex = hex::encode_upper(md(digest, &msg));
        if set(items, rec, "MD", &digest_hex) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}

/// Monte-Carlo 시험 (KISA 방식): 윈도우 크기 N = ⌊r/n⌋+1 (r=블록 비트,
/// n=다이제스트 비트). 매 외부 반복에서 처음 N개 MD를 Seed로 두고, 최근 N개를
/// 연접해 1000회 해시한 뒤 MD[1000+N-1]을 체크포인트로 출력하고 Seed로 잇는다.
fn mct(digest: MessageDigest, block: usize, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records(items);
    let mut seed = None;
    for rec in &recs {
        if let Some(s) = get(items, rec, "Seed") {
            seed = Some(hx(s)?);
            break;
        }
    }
    let mut s = match seed {
        Some(s) => s,
        None => return Ok(GenOutcome::Skipped("Seed 없음".into())),
    };

    let count_recs: Vec<_> = recs
        .iter()
        .filter(|r| get(items, r, "COUNT").is_some() && get(items, r, "MD").is_some())
        .cloned()
        .collect();

    // N = ⌊블록비트 / 다이제스트비트⌋ + 1  (= ⌊블록바이트 / 다이제스트바이트⌋ + 1)
    let n = block / digest.size() + 1;

    let mut filled = 0;
    for rec in &count_recs {
        // MD[0..N] = Seed, 이후 MD[k] = H(MD[k-N]||...||MD[k-1]).
        let mut chain: Vec<Vec<u8>> = vec![s.clone(); n];
        for k in n..1000 + n {
            let mut msg = Vec::with_capacity(n * s.len());
            for blk in &chain[k - n..k] {
                msg.extend_from_slice(blk);
            }
            chain.push(md(digest, &msg));
        }
        let out = chain[1000 + n - 1].clone();
        s = out.clone();
        if set(items, rec, "MD", &hex::encode_upper(&out)) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}
