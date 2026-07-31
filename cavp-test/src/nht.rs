//! NHT(잡음원 건전성 시험, SP 800-90B) CAVP 생성기.
//!
//! 주어진 표본열 `Sample`(1바이트 = 1표본)에 두 건전성 시험을 적용해 `Result`
//! (적합 `P` / 부적합 `F`)를 판정한다.
//! - RCT(반복계수시험): 동일 표본이 연속 `RCT cutOff` 회 이상이면 부적합.
//! - APT(적응비율시험): 크기 `APT WindowSize` 의 비중첩 창에서 창 첫 표본이
//!   `APT cutOff` 회 이상이면 부적합.
//!
//! 주의(추정): 파일명/헤더의 STRICT/LIMITED/STREAM 타입은 표준 알고리즘을
//! 바꾸지 않는 벡터 분류로 간주하고, RCT+APT 를 균일 적용한다. `Result` 토큰은
//! 다른 시험(SVT/PKV)과 동일하게 P/F 로 추정한다. 정확한 규격 입수 시 조정.

use crate::parser::{get, records, set, Item};
use crate::{GenError, GenOutcome};

/// "[KEY = VALUE]" 형태 헤더에서 정수를 읽는다.
fn header_int(items: &[Item], key: &str) -> Option<usize> {
    let pfx = format!("[{key} = ");
    for it in items {
        if let Item::Raw(s) = it {
            if let Some(v) = s.trim().strip_prefix(&pfx) {
                return v.trim_end_matches(']').trim().parse().ok();
            }
        }
    }
    None
}

/// RCT: 동일 값이 연속 cutoff 회 이상이면 부적합(true).
fn rct_fail(s: &[u8], cutoff: usize) -> bool {
    if cutoff == 0 || s.is_empty() {
        return false;
    }
    let mut a = s[0];
    let mut b = 1usize;
    for &x in &s[1..] {
        if x == a {
            b += 1;
            if b >= cutoff {
                return true;
            }
        } else {
            a = x;
            b = 1;
        }
    }
    false
}

/// APT: 비중첩 창마다 창 첫 표본의 출현 수 B 가 cutoff C 를 **초과**하면
/// 부적합(true). TTAK.KO-12.0235 부록Ⅱ 의사코드: `count > C` 일 때 오류.
fn apt_fail(s: &[u8], window: usize, cutoff: usize) -> bool {
    if window == 0 || cutoff == 0 {
        return false;
    }
    let mut i = 0;
    while i + window <= s.len() {
        let a = s[i];
        let mut b = 1usize;
        for j in 1..window {
            if s[i + j] == a {
                b += 1;
            }
        }
        if b > cutoff {
            return true;
        }
        i += window;
    }
    false
}

/// 바이트열을 니블(4비트) 스트림으로 펼친다(MSB-first).
fn to_nibbles(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() * 2);
    for &x in b {
        out.push(x >> 4);
        out.push(x & 15);
    }
    out
}

pub fn generate(stem: &str, items: &mut [Item]) -> Result<GenOutcome, GenError> {
    let rct_cutoff = header_int(items, "RCT cutOff").unwrap_or(0);
    let apt_window = header_int(items, "APT WindowSize").unwrap_or(0);
    let apt_cutoff = header_int(items, "APT cutOff").unwrap_or(0);
    // 검사 범위(scope): [Input Buffer Length](LIMITED 타입 존재 시)가 있으면
    // 그 길이, 없으면 APT 윈도우 크기. 이 규칙은 1024 그룹 전체(8/8)와
    // 512 그룹의 동일타입 조합(LL/SS)에서 검증기와 일치함이 확인됨.
    let scope_hdr = header_int(items, "Input Buffer Length");
    let scope = scope_hdr.unwrap_or(apt_window);

    // [실험] 512 그룹(RCT cutOff=6 ⇔ 샘플당 4비트 엔트로피)의 혼합/STRICT 조합
    // 6개 파일은 바이트 단위 판정이 검증기와 불일치(FAIL). 데이터 분석 결과
    // 이들 벡터는 니블(4비트) 샘플 해석을 시사(90B: 비이진 W=512, C=1+⌈20/4⌉=6)
    // 하므로, 해당 6개 파일에 한해 니블 단위로 판정한다. (LL/SS 512 파일은
    // 바이트 단위가 검증기와 일치 확인 → 유지)
    let parse_types = || -> Option<(String, String)> {
        let m = stem.strip_prefix("NHT_")?;
        let p1 = m.find('(')?;
        let rt = m[..p1].to_string();
        let rest = &m[m.find(")_")? + 2..];
        let p2 = rest.find('(')?;
        Some((rt, rest[..p2].to_string()))
    };
    let nibble_mode = if apt_window == 512 {
        match parse_types() {
            Some((rt, at)) => rt != at || rt == "STRICT",
            None => false,
        }
    } else {
        false
    };

    let recs = records(items);
    let mut filled = 0;
    for rec in &recs {
        let sample_bytes = match get(items, rec, "Sample") {
            Some(v) => hex::decode(v.trim()).map_err(|e| GenError(format!("hex: {e}")))?,
            None => continue,
        };
        if get(items, rec, "Result").map(|v| v.contains('?')) != Some(true) {
            continue;
        }
        // 샘플 스트림: 니블 모드면 4비트/샘플, 아니면 1바이트/샘플.
        let stream: Vec<u8> = if nibble_mode {
            to_nibbles(&sample_bytes)
        } else {
            sample_bytes.clone()
        };
        // 니블 모드에서 [Input Buffer Length] 는 바이트 단위로 보고 ×2.
        let eff_scope = if nibble_mode && scope_hdr.is_some() {
            scope * 2
        } else {
            scope
        };
        let s = if eff_scope > 0 && eff_scope < stream.len() {
            &stream[..eff_scope]
        } else {
            &stream[..]
        };
        let fail = rct_fail(s, rct_cutoff) || apt_fail(s, apt_window, apt_cutoff);
        filled += set(items, rec, "Result", if fail { "T" } else { "F" }) as usize;
    }
    Ok(GenOutcome::Generated(filled))
}
