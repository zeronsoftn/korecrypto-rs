//! 블록암호 CAVP 생성기 (KAT / MMT / MCT).
//!
//! 모든 운영모드를 korecrypto 의 EVP 인터페이스로 처리한다(ECB/CBC/CTR/OFB/
//! CFB1/8/32/64/128). CFB1 은 비트열('0'/'1') 표기이며, EVP 의
//! `EVP_CIPH_FLAG_LENGTH_BITS`(Crypter::set_flags) + `update_bits` 로 비트
//! 단위 입력을 처리한다. MCT 의 내부 블록 연산(E)은 검증기준 의사코드대로
//! ECB 단일 블록을 쓴다.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};
use korecrypto::symm::{Cipher, Crypter, Mode};

const EVP_CIPH_FLAG_LENGTH_BITS: i32 = 0x2000;

/// "ARIA-128" + "ECB" → boring Cipher. 미지원 조합은 None.
fn lookup(algo: &str, mode: &str) -> Option<Cipher> {
    Some(match (algo, mode) {
        ("AES-128", "ECB") => Cipher::aes_128_ecb(),
        ("AES-128", "CBC") => Cipher::aes_128_cbc(),
        ("AES-128", "CTR") => Cipher::aes_128_ctr(),
        ("AES-192", "ECB") => Cipher::aes_192_ecb(),
        ("AES-192", "CBC") => Cipher::aes_192_cbc(),
        ("AES-192", "CTR") => Cipher::aes_192_ctr(),
        ("AES-256", "ECB") => Cipher::aes_256_ecb(),
        ("AES-256", "CBC") => Cipher::aes_256_cbc(),
        ("AES-256", "CTR") => Cipher::aes_256_ctr(),
        ("ARIA-128", "ECB") => Cipher::aria_128_ecb(),
        ("ARIA-128", "CBC") => Cipher::aria_128_cbc(),
        ("ARIA-128", "CTR") => Cipher::aria_128_ctr(),
        ("ARIA-192", "ECB") => Cipher::aria_192_ecb(),
        ("ARIA-192", "CBC") => Cipher::aria_192_cbc(),
        ("ARIA-192", "CTR") => Cipher::aria_192_ctr(),
        ("ARIA-256", "ECB") => Cipher::aria_256_ecb(),
        ("ARIA-256", "CBC") => Cipher::aria_256_cbc(),
        ("ARIA-256", "CTR") => Cipher::aria_256_ctr(),
        ("SEED-128", "ECB") => Cipher::seed_ecb(),
        ("SEED-128", "CBC") => Cipher::seed_cbc(),
        ("SEED-128", "CTR") => Cipher::seed_ctr(),
        ("LEA-128", "ECB") => Cipher::lea_128_ecb(),
        ("LEA-128", "CBC") => Cipher::lea_128_cbc(),
        ("LEA-128", "CTR") => Cipher::lea_128_ctr(),
        ("LEA-192", "ECB") => Cipher::lea_192_ecb(),
        ("LEA-192", "CBC") => Cipher::lea_192_cbc(),
        ("LEA-192", "CTR") => Cipher::lea_192_ctr(),
        ("LEA-256", "ECB") => Cipher::lea_256_ecb(),
        ("LEA-256", "CBC") => Cipher::lea_256_cbc(),
        ("LEA-256", "CTR") => Cipher::lea_256_ctr(),
        ("HIGHT", "ECB") => Cipher::hight_ecb(),
        ("HIGHT", "CBC") => Cipher::hight_cbc(),
        ("HIGHT", "CTR") => Cipher::hight_ctr(),
        _ => return None,
    })
}

/// OFB / CFB(1/8/32/64/128) 의 EVP Cipher. 미지원 조합은 None.
fn stream_lookup(algo: &str, mode: &str) -> Option<Cipher> {
    Some(match (algo, mode) {
        ("AES-128", "OFB") => Cipher::aes_128_ofb(),
        ("AES-192", "OFB") => Cipher::aes_192_ofb(),
        ("AES-256", "OFB") => Cipher::aes_256_ofb(),
        ("AES-128", "CFB128") => Cipher::aes_128_cfb128(),
        ("AES-192", "CFB128") => Cipher::aes_192_cfb128(),
        ("AES-256", "CFB128") => Cipher::aes_256_cfb128(),
        ("AES-128", "CFB64") => Cipher::aes_128_cfb64(),
        ("AES-192", "CFB64") => Cipher::aes_192_cfb64(),
        ("AES-256", "CFB64") => Cipher::aes_256_cfb64(),
        ("AES-128", "CFB8") => Cipher::aes_128_cfb8(),
        ("AES-192", "CFB8") => Cipher::aes_192_cfb8(),
        ("AES-256", "CFB8") => Cipher::aes_256_cfb8(),
        ("AES-128", "CFB1") => Cipher::aes_128_cfb1(),
        ("AES-192", "CFB1") => Cipher::aes_192_cfb1(),
        ("AES-256", "CFB1") => Cipher::aes_256_cfb1(),
        ("ARIA-128", "OFB") => Cipher::aria_128_ofb(),
        ("ARIA-192", "OFB") => Cipher::aria_192_ofb(),
        ("ARIA-256", "OFB") => Cipher::aria_256_ofb(),
        ("ARIA-128", "CFB128") => Cipher::aria_128_cfb128(),
        ("ARIA-192", "CFB128") => Cipher::aria_192_cfb128(),
        ("ARIA-256", "CFB128") => Cipher::aria_256_cfb128(),
        ("ARIA-128", "CFB64") => Cipher::aria_128_cfb64(),
        ("ARIA-192", "CFB64") => Cipher::aria_192_cfb64(),
        ("ARIA-256", "CFB64") => Cipher::aria_256_cfb64(),
        ("ARIA-128", "CFB8") => Cipher::aria_128_cfb8(),
        ("ARIA-192", "CFB8") => Cipher::aria_192_cfb8(),
        ("ARIA-256", "CFB8") => Cipher::aria_256_cfb8(),
        ("ARIA-128", "CFB1") => Cipher::aria_128_cfb1(),
        ("ARIA-192", "CFB1") => Cipher::aria_192_cfb1(),
        ("ARIA-256", "CFB1") => Cipher::aria_256_cfb1(),
        ("LEA-128", "OFB") => Cipher::lea_128_ofb(),
        ("LEA-192", "OFB") => Cipher::lea_192_ofb(),
        ("LEA-256", "OFB") => Cipher::lea_256_ofb(),
        ("LEA-128", "CFB128") => Cipher::lea_128_cfb128(),
        ("LEA-192", "CFB128") => Cipher::lea_192_cfb128(),
        ("LEA-256", "CFB128") => Cipher::lea_256_cfb128(),
        ("LEA-128", "CFB64") => Cipher::lea_128_cfb64(),
        ("LEA-192", "CFB64") => Cipher::lea_192_cfb64(),
        ("LEA-256", "CFB64") => Cipher::lea_256_cfb64(),
        ("LEA-128", "CFB8") => Cipher::lea_128_cfb8(),
        ("LEA-192", "CFB8") => Cipher::lea_192_cfb8(),
        ("LEA-256", "CFB8") => Cipher::lea_256_cfb8(),
        ("LEA-128", "CFB1") => Cipher::lea_128_cfb1(),
        ("LEA-192", "CFB1") => Cipher::lea_192_cfb1(),
        ("LEA-256", "CFB1") => Cipher::lea_256_cfb1(),
        ("SEED-128", "OFB") => Cipher::seed_ofb(),
        ("SEED-128", "CFB128") => Cipher::seed_cfb128(),
        ("SEED-128", "CFB64") => Cipher::seed_cfb64(),
        ("SEED-128", "CFB8") => Cipher::seed_cfb8(),
        ("SEED-128", "CFB1") => Cipher::seed_cfb1(),
        ("HIGHT", "OFB") => Cipher::hight_ofb(),
        ("HIGHT", "CFB64") => Cipher::hight_cfb64(),
        ("HIGHT", "CFB32") => Cipher::hight_cfb32(),
        ("HIGHT", "CFB8") => Cipher::hight_cfb8(),
        ("HIGHT", "CFB1") => Cipher::hight_cfb1(),
        _ => return None,
    })
}

/// 패딩 없이 한 번에 암/복호화한다(블록 배수 또는 스트림 모드 입력 가정).
fn crypt(
    cipher: Cipher,
    key: &[u8],
    iv: Option<&[u8]>,
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, GenError> {
    let mode = if encrypt {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };
    let mut c = Crypter::new(cipher, mode, key, iv).map_err(|e| GenError(e.to_string()))?;
    c.pad(false);
    let mut out = vec![0u8; input.len() + cipher.block_size()];
    let n = c
        .update(input, &mut out)
        .map_err(|e| GenError(e.to_string()))?;
    let m = c
        .finalize(&mut out[n..])
        .map_err(|e| GenError(e.to_string()))?;
    out.truncate(n + m);
    Ok(out)
}

fn hx(s: &str) -> Result<Vec<u8>, GenError> {
    hex::decode(s).map_err(|e| GenError(format!("hex: {e}")))
}

/// 파일명에서 (ALGO, MODE, TESTTYPE) 를 추출한다.
/// 예: "ARIA-128_(ECB)_KAT" → ("ARIA-128","ECB","KAT").
fn parse_name(stem: &str) -> Option<(String, String, String)> {
    let open = stem.find('(')?;
    let close = stem.find(')')?;
    let algo = stem[..open].trim_end_matches('_').to_string();
    let mode = stem[open + 1..close].to_string();
    let rest = stem[close + 1..].trim_start_matches('_');
    let testtype = rest.to_string();
    Some((algo, mode, testtype))
}

/// 블록암호 파일을 처리한다. 지원하면 채워진 Item 목록을, 미지원이면 Skipped.
pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let (algo, mode, testtype) = match parse_name(stem) {
        Some(t) => t,
        None => return Ok(GenOutcome::Skipped("파일명 파싱 실패".into())),
    };

    // OFB: EVP OFB. MCT 는 검증기준 의사코드대로 ECB 로 처리.
    if mode == "OFB" {
        let cipher = match stream_lookup(&algo, &mode) {
            Some(c) => c,
            None => return Ok(GenOutcome::Skipped(format!("미지원 암호: {algo}"))),
        };
        return match testtype.as_str() {
            "KAT" | "MMT" => kat_mmt(cipher, items),
            "MCT" => mct(&algo, "OFB", items),
            other => Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
        };
    }

    // CFB{1,8,32,64,128}: EVP CFB. CFB1 은 비트 경로(set_flags+update_bits),
    // 그 외는 바이트 EVP. MCT 는 ECB 의사코드로 처리(cfb_mct).
    if let Some(width) = mode.strip_prefix("CFB").and_then(|w| w.parse::<u32>().ok()) {
        let cipher = match stream_lookup(&algo, &mode) {
            Some(c) => c,
            None => return Ok(GenOutcome::Skipped(format!("미지원 암호: {algo} {mode}"))),
        };
        return match testtype.as_str() {
            "KAT" | "MMT" => {
                if width == 1 {
                    cfb1_kat_mmt(cipher, items)
                } else {
                    kat_mmt(cipher, items)
                }
            }
            "MCT" => cfb_mct(&algo, width, items),
            other => Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
        };
    }

    let cipher = match lookup(&algo, &mode) {
        Some(c) => c,
        None => return Ok(GenOutcome::Skipped(format!("미지원 모드: {algo} {mode}"))),
    };

    match testtype.as_str() {
        "KAT" | "MMT" => kat_mmt(cipher, items),
        "MCT" => match mode.as_str() {
            "ECB" | "CBC" | "CTR" => mct(&algo, &mode, items),
            _ => Ok(GenOutcome::Skipped(format!("MCT {mode} 미구현"))),
        },
        other => Ok(GenOutcome::Skipped(format!("미지원 시험유형: {other}"))),
    }
}

/// 레코드의 PT/CT 중 어느 쪽이 `?`(질의)인지로 방향과 입력 필드를 판별한다.
/// (target_key, input_str, encrypt) 반환. 둘 다 값이거나 둘 다 ? 이면 None.
fn direction<'a>(items: &'a [Item], rec: &Vec<usize>) -> Option<(&'static str, &'a str, bool)> {
    let pt = get(items, rec, "PT");
    let ct = get(items, rec, "CT");
    let ct_query = matches!(pt, Some(p) if p != "?") && matches!(ct, Some("?"));
    let pt_query = matches!(ct, Some(c) if c != "?") && matches!(pt, Some("?"));
    if ct_query {
        Some(("CT", pt.unwrap(), true))
    } else if pt_query {
        Some(("PT", ct.unwrap(), false))
    } else {
        None
    }
}

/// CFB 입력 문자열을 (패킹 바이트, 비트수)로 변환한다. CFB1 은 '0'/'1' 비트열.
fn parse_cfb_input(width: u32, s: &str) -> Result<(Vec<u8>, usize), GenError> {
    let s = s.trim();
    if width == 1 {
        let total = s.len();
        let mut bytes = vec![0u8; total.div_ceil(8)];
        for (i, c) in s.chars().enumerate() {
            match c {
                '0' => {}
                '1' => bytes[i / 8] |= 1 << (7 - (i % 8)),
                _ => return Err(GenError(format!("CFB1 비트열 오류: {c}"))),
            }
        }
        Ok((bytes, total))
    } else {
        let bytes = hx(s)?;
        let total = bytes.len() * 8;
        Ok((bytes, total))
    }
}

/// CFB 출력(패킹 바이트)을 표기 문자열로. CFB1 은 '0'/'1' 비트열, 그 외는 hex.
fn format_cfb_output(width: u32, bytes: &[u8], total_bits: usize) -> String {
    if width == 1 {
        let mut out = String::with_capacity(total_bits);
        for i in 0..total_bits {
            let bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
            out.push(if bit == 1 { '1' } else { '0' });
        }
        out
    } else {
        hex::encode_upper(&bytes[..total_bits / 8])
    }
}

/// CFB1 KAT/MMT: EVP CFB1(비트 경로). '0'/'1' 비트열 입출력,
/// `EVP_CIPH_FLAG_LENGTH_BITS` + `update_bits` 로 정확한 비트수 처리.
fn cfb1_kat_mmt(cipher: Cipher, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records(items);
    let mut filled = 0usize;
    for rec in &recs {
        let key = match get(items, rec, "KEY") {
            Some(k) => hx(k)?,
            None => continue,
        };
        let iv = hx(get(items, rec, "IV").unwrap_or(""))?;
        let (target, input_str, encrypt) = match direction(items, rec) {
            Some(d) => d,
            None => continue,
        };
        let (input, total_bits) = parse_cfb_input(1, input_str)?;
        let mode = if encrypt {
            Mode::Encrypt
        } else {
            Mode::Decrypt
        };
        let mut c =
            Crypter::new(cipher, mode, &key, Some(&iv)).map_err(|e| GenError(e.to_string()))?;
        c.pad(false);
        c.set_flags(EVP_CIPH_FLAG_LENGTH_BITS);
        let mut out = vec![0u8; total_bits.div_ceil(8) + 1];
        c.update_bits(&input, total_bits, &mut out)
            .map_err(|e| GenError(e.to_string()))?;
        let out_str = format_cfb_output(1, &out, total_bits);
        if set(items, rec, target, &out_str) {
            filled += 1;
        }
    }
    Ok(GenOutcome::Generated(filled))
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// 빅엔디안 카운터 블록을 1 증가시킨다(전체 블록 길이 캐리).
fn inc_be(v: &[u8]) -> Vec<u8> {
    let mut out = v.to_vec();
    for i in (0..out.len()).rev() {
        if out[i] == 0xff {
            out[i] = 0;
        } else {
            out[i] += 1;
            break;
        }
    }
    out
}

/// 한 블록 암/복호(ECB, 패딩 없음).
fn block(cipher: Cipher, key: &[u8], input: &[u8], encrypt: bool) -> Result<Vec<u8>, GenError> {
    crypt(cipher, key, None, input, encrypt)
}

// ===== 비트열 헬퍼 (CFB MCT 용) =====

fn bytes_to_bits(bytes: &[u8], n: usize) -> Vec<bool> {
    (0..n)
        .map(|i| (bytes[i / 8] >> (7 - (i % 8))) & 1 == 1)
        .collect()
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

/// CFB MCT(검증기준 V3.0, 일반 피드백 폭 s).
///
/// 블록 b비트, 세그먼트 s비트, b/s = 블록당 세그먼트 수. 의사코드(CFB1/8/128)를
/// 임의 폭으로 일반화한다. 암호화 방향만 사용된다(검증 벡터 기준).
/// - 내부 E 는 ECB 단일 블록.
/// - PT[j+1] = (j<b/s ? IV 의 j번째 s비트 세그먼트 : CT[j-b/s])
/// - 피드백(CF) = 시프트 레지스터(상위 s비트 버리고 CT 세그먼트 추가).
/// - 외부 갱신: Key ^= (CT 비트열의 끝 keylen 비트), IV[i+1]=끝 b비트,
///   PT[0]=CT[999-b/s].
fn cfb_mct(algo: &str, width: u32, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let ecb = lookup(algo, "ECB").ok_or_else(|| GenError("ECB 미지원".into()))?;
    let s = width as usize;
    let bl = ecb.block_size(); // 바이트
    let b = bl * 8; // 블록 비트
    if b % s != 0 {
        return Ok(GenOutcome::Skipped(format!("CFB{width}: 블록 비정수 분할")));
    }
    let seg_per_block = b / s;

    let recs = records(items);
    let count_recs: Vec<_> = recs
        .iter()
        .filter(|r| get(items, r, "COUNT").is_some())
        .cloned()
        .collect();
    if count_recs.is_empty() {
        return Ok(GenOutcome::Generated(0));
    }

    let first = &count_recs[0];
    let mut key = hx(get(items, first, "KEY").ok_or_else(|| GenError("KEY 없음".into()))?)?;
    let iv0 = hx(get(items, first, "IV").ok_or_else(|| GenError("IV 없음".into()))?)?;
    let mut iv_bits = bytes_to_bits(&iv0, b);
    // 방향은 암호화만 지원(검증 벡터 기준).
    let pt0_str = get(items, first, "PT").ok_or_else(|| GenError("PT 없음".into()))?;
    if pt0_str == "?" {
        return Ok(GenOutcome::Skipped("CFB MCT 복호 방향 미지원".into()));
    }
    let (pt0_bytes, pt0_bits_len) = parse_cfb_input(width, pt0_str)?;
    if pt0_bits_len != s {
        return Err(GenError(format!(
            "CFB{width} PT[0] 비트수 {pt0_bits_len} != {s}"
        )));
    }
    let mut pt0_bits = bytes_to_bits(&pt0_bytes, s);

    let keylen_bits = key.len() * 8;
    let mut filled = 0usize;

    for rec in &count_recs {
        // 입력값 기록(KEY/IV/PT[0]).
        set(items, rec, "KEY", &hex::encode_upper(&key));
        set(
            items,
            rec,
            "IV",
            &hex::encode_upper(bits_to_bytes(&iv_bits)),
        );
        set(
            items,
            rec,
            "PT",
            &format_cfb_output(width, &bits_to_bytes(&pt0_bits), s),
        );

        // 내부 1000회: 모든 CT 비트를 누적한다.
        let mut ct_stream: Vec<bool> = Vec::with_capacity(1000 * s);
        let mut reg = iv_bits.clone(); // b비트 시프트 레지스터(j=0 입력은 IV)
        let mut pt_j = pt0_bits.clone(); // 현재 PT 세그먼트(s비트)

        for j in 0..1000usize {
            let o = block(ecb, &key, &bits_to_bytes(&reg), true)?;
            let o_bits = bytes_to_bits(&o, b);
            // CT[j] = PT[j] xor MSB_s(E(reg))
            let ct_j: Vec<bool> = (0..s).map(|k| pt_j[k] ^ o_bits[k]).collect();
            ct_stream.extend_from_slice(&ct_j);

            // 다음 PT 세그먼트 계산(마지막 반복 제외).
            if j < 999 {
                let pt_next: Vec<bool> = if j < seg_per_block {
                    iv_bits[j * s..j * s + s].to_vec()
                } else {
                    let idx = j - seg_per_block; // CT 세그먼트 인덱스
                    ct_stream[idx * s..idx * s + s].to_vec()
                };
                pt_j = pt_next;
            }

            // CF[j+1] = LSB_{b-s}(reg) || CT[j]
            let mut next_reg = reg[s..b].to_vec();
            next_reg.extend_from_slice(&ct_j);
            reg = next_reg;
        }

        // 마지막 출력 CT[999].
        let total = ct_stream.len(); // = 1000*s
        let last_ct = &ct_stream[total - s..total];
        let out_str = format_cfb_output(width, &bits_to_bytes(last_ct), s);
        if set(items, rec, "CT", &out_str) {
            filled += 1;
        }

        // 외부 갱신.
        // Key ^= (CT 비트열의 끝 keylen 비트)
        let key_tail = bits_to_bytes(&ct_stream[total - keylen_bits..total]);
        key = xor(&key, &key_tail);
        // IV[i+1] = 끝 b비트
        iv_bits = ct_stream[total - b..total].to_vec();
        // PT[0] = CT[999 - b/s]
        let pt0_idx = 999 - seg_per_block;
        pt0_bits = ct_stream[pt0_idx * s..pt0_idx * s + s].to_vec();
    }

    Ok(GenOutcome::Generated(filled))
}

/// 블록암호 MCT(검증기준 V3.0). ECB/CBC/CTR/OFB, 암호화/복호화 지원.
/// 방향은 COUNT=0 레코드에서 PT(=?→복호) / CT(=?→암호) 위치로 판별한다.
fn mct(algo: &str, mode: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let ecb = lookup(algo, "ECB").ok_or_else(|| GenError("ECB 미지원".into()))?;
    let recs = records(items);
    let count_recs: Vec<_> = recs
        .iter()
        .filter(|r| get(items, r, "COUNT").is_some())
        .cloned()
        .collect();
    if count_recs.is_empty() {
        return Ok(GenOutcome::Generated(0));
    }

    // 초기값(COUNT=0).
    let first = &count_recs[0];
    let mut key = hx(get(items, first, "KEY").ok_or_else(|| GenError("KEY 없음".into()))?)?;
    // CTR 모드는 초기벡터를 "CTR" 필드에서, 그 외(CBC/OFB)는 "IV" 에서 읽는다.
    let iv_field = if mode == "CTR" { "CTR" } else { "IV" };
    let mut iv = match get(items, first, iv_field) {
        Some(v) => hx(v)?,
        None => Vec::new(),
    };
    let encrypt = get(items, first, "PT").map(|s| s != "?").unwrap_or(false);
    // 입력 텍스트(암호화면 PT, 복호화면 CT).
    let in_key = if encrypt { "PT" } else { "CT" };
    let out_key = if encrypt { "CT" } else { "PT" };
    let mut text = hx(get(items, first, in_key).ok_or_else(|| GenError("입력 없음".into()))?)?;
    let klen = key.len();

    let mut filled = 0;
    for rec in &count_recs {
        // 이 외부 반복의 입력값을 레코드에 기록(이미 있을 수 있음).
        set(items, rec, "KEY", &hex::encode_upper(&key));
        if !iv.is_empty() {
            set(items, rec, iv_field, &hex::encode_upper(&iv));
        }
        set(items, rec, in_key, &hex::encode_upper(&text));

        // 1000회 내부 루프, 마지막 두 출력 블록 보관.
        let mut prev = Vec::new(); // 출력[j-1]
        let mut last = Vec::new(); // 출력[j]
        match (mode, encrypt) {
            ("ECB", true) => {
                let mut pt = text.clone();
                for _ in 0..1000 {
                    let ct = block(ecb, &key, &pt, true)?;
                    prev = std::mem::replace(&mut last, ct.clone());
                    pt = ct;
                }
                text = last.clone();
            }
            ("ECB", false) => {
                let mut ct = text.clone();
                for _ in 0..1000 {
                    let pt = block(ecb, &key, &ct, false)?;
                    prev = std::mem::replace(&mut last, pt.clone());
                    ct = pt;
                }
                text = last.clone();
            }
            ("CBC", true) => {
                let mut cv = iv.clone();
                let mut pt = text.clone();
                for _ in 0..1000 {
                    let ct = block(ecb, &key, &xor(&pt, &cv), true)?;
                    pt = cv.clone(); // PT[j+1] = CT[j-1] (=IV for j=0)
                    cv = ct.clone();
                    prev = std::mem::replace(&mut last, ct);
                }
                iv = last.clone();
                text = prev.clone(); // 다음 외부 PT0 = CT[998]
            }
            ("CBC", false) => {
                let mut cv = iv.clone();
                let mut ct = text.clone();
                for _ in 0..1000 {
                    let pt = xor(&block(ecb, &key, &ct, false)?, &cv);
                    cv = ct.clone();
                    ct = pt.clone();
                    prev = std::mem::replace(&mut last, pt);
                }
                iv = last.clone();
                text = prev.clone();
            }
            // CTR MCT(KISA): 카운터를 내부 1000회 동안 연속 증가시키고
            // 다음 입력은 직전 출력(PT[j+1]=CT[j]). 다음 외부 카운터는 누적값.
            ("CTR", _) => {
                let mut counter = iv.clone();
                let mut input = text.clone();
                for _ in 0..1000 {
                    let ks = block(ecb, &key, &counter, true)?;
                    let outb = xor(&input, &ks);
                    prev = std::mem::replace(&mut last, outb.clone());
                    input = outb;
                    counter = inc_be(&counter);
                }
                iv = counter; // CTR[i+1] = 누적 카운터
                text = last.clone(); // 다음 외부 입력 = 마지막 출력
            }
            // OFB MCT(검증기준 V3.0): OT[0]=E(IV), OT[j]=E(OT[j-1]).
            // CT[j]=PT[j] xor OT[j]. PT[j+1]= (j==0? IV : CT[j-1]).
            // IV[i+1]=CT[999], PT[0]=CT[998], KEY^=CT 끝부분.
            ("OFB", _) => {
                let mut ot_prev = Vec::new(); // OT[j-1]
                let mut pt = text.clone(); // PT[j]
                let mut ct_prev = Vec::new(); // CT[j-1]
                for j in 0..1000 {
                    let ot = if j == 0 {
                        block(ecb, &key, &iv, true)?
                    } else {
                        block(ecb, &key, &ot_prev, true)?
                    };
                    let ct = xor(&pt, &ot);
                    pt = if j == 0 { iv.clone() } else { ct_prev.clone() }; // PT[j+1]=CT[j-1]
                    ct_prev = ct.clone();
                    ot_prev = ot;
                    prev = std::mem::replace(&mut last, ct);
                }
                iv = last.clone(); // IV[i+1] = CT[999]
                text = prev.clone(); // PT[0] = CT[998]
            }
            _ => unreachable!(),
        }

        // 출력 기록.
        if set(items, rec, out_key, &hex::encode_upper(&last)) {
            filled += 1;
        }

        // 키 갱신: 마지막 두 출력 블록(prev||last)의 끝에서 klen 바이트와 XOR.
        let mut tail = prev.clone();
        tail.extend_from_slice(&last);
        let start = tail.len() - klen;
        key = xor(&key, &tail[start..]);

        // 다음 외부 입력: ECB 는 마지막 출력, CBC 는 위에서 text 설정됨.
        if mode == "ECB" {
            text = last.clone();
        }
    }
    Ok(GenOutcome::Generated(filled))
}

/// KAT/MMT: 각 레코드는 독립적이며 PT 또는 CT 중 하나가 `?`(방향 자동판별).
fn kat_mmt(cipher: Cipher, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let recs = records(items);
    let mut filled = 0usize;
    for rec in &recs {
        let key = match get(items, rec, "KEY") {
            Some(k) => hx(k)?,
            None => continue, // 헤더 레코드 등
        };
        // 초기벡터: CBC 는 IV, CTR 은 CTR(카운터 블록) 필드를 사용한다.
        let iv = match get(items, rec, "IV").or_else(|| get(items, rec, "CTR")) {
            Some(v) => Some(hx(v)?),
            None => None,
        };
        let (target_key, input_str, encrypt) = match direction(items, rec) {
            Some(d) => d,
            None => continue,
        };
        let input = hx(input_str)?;
        let result = crypt(cipher, &key, iv.as_deref(), &input, encrypt)?;

        // 대상 필드에 결과 기록.
        for &i in rec {
            if let Item::Field {
                key: k,
                value,
                query,
            } = &mut items[i]
            {
                if k == target_key && *query {
                    *value = hex::encode_upper(&result);
                    *query = false;
                    filled += 1;
                }
            }
        }
    }
    Ok(GenOutcome::Generated(filled))
}
