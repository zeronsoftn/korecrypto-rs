//! KCMVP 엔트로피 평가(SP 800-90B)용 잡음원 샘플 파일 생성 지원.
//!
//! 국정원 "암호모듈 사전검증 서비스"의 엔트로피 평가는 난수발생기에 입력되는
//! 잡음원의 가공되지 않은(raw) 출력 25만 개를 다음 형식의 텍스트 파일로 요구한다:
//!
//! ```text
//! Len = 8, Num = 250000
//!
//! <샘플 데이터: 샘플당 ceil(Len/8) 바이트를 16진수로, 공백 구분>
//! ```
//!
//! - Line 1: 고정 형식 `Len = <샘플 비트수>, Num = <샘플 개수>`
//! - Line 2: 빈 줄
//! - Line 3: 잡음원 데이터(16진수). 절단(truncation)만 허용되는 원시 샘플.
//!
//! 샘플 수집은 반드시 실제 KCMVP(FIPS) 모듈의 잡음원 경로
//! (`KCMVP_entropy_raw_noise_samples` → `bssl::entropy::GetSamples`)를 통해야 한다.

/// KCMVP 엔트로피 평가가 요구하는 고정 샘플 개수.
pub const NUM_SAMPLES: usize = 250_000;

/// 8 비트 샘플(바이트 하나 = 샘플 하나)을 KCMVP 평가 파일 형식의 문자열로 만든다.
///
/// `bits` 는 단일 샘플의 비트 크기(`Len`), `samples` 는 샘플당 1 바이트인 8 비트
/// 샘플 배열이다.
pub fn format_sample_file(bits: u32, samples: &[u8]) -> String {
    // 헤더 + 빈 줄 + 데이터. 데이터는 대문자 16진수 바이트를 공백으로 구분한다.
    let mut out = String::with_capacity(64 + samples.len() * 3);
    out.push_str(&format!("Len = {}, Num = {}\n\n", bits, samples.len()));
    for b in samples {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0x0f));
    }
    out.push('\n');
    out
}

fn hex_nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'A' + (v - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_data() {
        let s = format_sample_file(8, &[0xbf, 0x01, 0xaf, 0x00]);
        let mut lines = s.lines();
        assert_eq!(lines.next().unwrap(), "Len = 8, Num = 4");
        assert_eq!(lines.next().unwrap(), "");
        assert_eq!(lines.next().unwrap(), "BF01AF00");
    }
}
