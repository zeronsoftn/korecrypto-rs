# cavp-test — KCMVP CAVP `.rsp` 생성기

KISA KCMVP CAVP 시험 요청 파일로부터 응답 파일(`.rsp`)을 생성한다.
`korecrypto` 라이브러리를 직접 링크하여 알고리즘을 구동한다.

## 입력/출력

- 입력: `*.sam` — **응답 템플릿**. 요청 필드 + 답을 채울 자리(`= ?`).
  (`*.req` 는 답 필드가 없는 요청 원본; 본 생성기는 `.sam` 을 사용한다.)
- 출력: 같은 이름의 `*.rsp` — `?` 를 계산값으로 채운 응답.

서명/암호화 방향(enc/dec, gen/ver)은 별도 헤더가 아니라 **어느 필드가 `?` 인지**로
판별한다.

## 사용법

```bash
cargo run --release           # 현재 디렉터리의 모든 *.sam 처리
cargo run --release -- DIR    # DIR 안의 *.sam 처리
cargo run --release -- a.sam b.sam
```

처리 후 생성/건너뜀/오류 요약과, 건너뛴 사유별 집계를 출력한다.

## 현재 지원 범위 (791개 중 264개 생성, 오류 0)

| 패밀리 | 상태 |
|---|---|
| 블록암호 KAT/MMT — ECB/CBC/CTR (AES·ARIA·SEED·LEA·HIGHT), AES-OFB | ✅ |
| 블록암호 MCT — ECB/CBC (암호화·복호화) | ✅ |
| 해시 SHA2/SHA3/LSH — LMT/SMT/MCT | ✅ |
| Hash_DRBG / HMAC_DRBG (SHA2/SHA3/LSH, no PR·use PR) | ✅ |
| GCM (AE/AD) — AES·ARIA·LEA·SEED | ✅ |
| KBKDF — Counter 모드 + HMAC PRF | ✅ |
| PBKDF2 — HMAC PRF | ✅ |
| DH 키합의(KAT) | ✅ |
| ECDH 키합의(소수체 P-224/256, KAKAT) | ✅ |
| ECDSA(P-224/256/384/521) — KPG/PKV/SGT/SVT | ✅ |
| RSA-PSS — SVT(검증) | ✅ |
| EC-KCDSA / KCDSA | ⏸ 보류(PLAN.md Phase 4) |
| 블록암호 MCT — CTR/OFB | ⬜ 후속(CTR-MCT 규격 불확실) |
| RSAES, RSA-PSS KPG/SGT | ⬜ 후속(OAEP md 설정·랜덤 솔트) |
| CCM / CMAC / KBKDF FB·DP·CMAC / CTR_DRBG | ⬜ 보류(라이브러리 바인딩 필요) |

구조적 미지원(라이브러리에 암호기능 부재 또는 바인딩 제약):
- CCM: EVP_AEAD CCM 바인딩이 nonce 12·tag 16 고정 → CAVP 의 가변 Nlen/Tlen 미수용.
- CMAC: boring Rust API 에 CMAC 래퍼 없음(ffi `CMAC_CTX` 바인딩 추가 필요).
- CTR_DRBG: BoringSSL CTR_DRBG 는 AES-256 고정·미노출.
- CFB1/8/64/128·국산암호 OFB: 라이브러리에 모드 미노출.
- (보류) EC-KCDSA 이진체 곡선·곡선≠해시 길이·KCDSA 도메인 파라미터 생성.

검증:
- AES-128 ECB KAT → NIST AESAVS VarTxt 기지값 일치.
- AES-128 ECB MCT → COUNT 연쇄 및 키갱신(XOR) 이 AESAVS 정의와 일치.
- SHA-256("") → e3b0c442... 기지값 일치.

부수 수정(커밋됨): HMAC 의 pad/key_block 버퍼가 `EVP_MAX_MD_BLOCK_SIZE`(128)로
잡혀 LSH-512(블록 256)·SHA3-224/256 기반 HMAC 에서 스택 오버플로로 abort 되던
라이브러리 버그를 256 으로 상향 수정(boringssl include/openssl/digest.h).
