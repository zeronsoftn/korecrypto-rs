# PLAN — korecrypto: BoringSSL/boring 기반 KCMVP 검증용 암호 모듈 구축 계획

> 목표: `cloudflare/boring`(Rust) + 번들된 `boringssl`(C)을 수정하여, 국정원 **KCMVP**(한국형 암호모듈 검증제도, KS X ISO/IEC 19790 기반) 인증을 받을 수 있는 암호 모듈로 만든다.
>
> 핵심 전략: BoringSSL이 이미 보유한 **FIPS 140 모듈 인프라**(암호경계 `bcm.cc`, 무결성 검사, 가동 전 자가시험 KAT, service indicator)를 **KCMVP 모드**로 재구성하고, KCMVP 검증대상에 들어가지만 BoringSSL에 없는 **국산 알고리즘**(ARIA·SEED·LEA·HIGHT·LSH·KCDSA·EC-KCDSA·Hash/HMAC_DRBG·KBKDF)을 EVP 계층 및 암호경계 안에 추가한다.

---

## 1. KCMVP 개요 및 요구사항

KCMVP는 국가·공공기관 도입 보안제품에 사용되는 암호모듈을 국정원이 검증하는 제도로, 시험 기준은 **KS X ISO/IEC 19790(암호모듈 보안요구사항)** 및 **KS X ISO/IEC 24759(시험 요구사항)**, 그리고 KISA가 고시하는 **검증대상 암호알고리즘** 목록이다. (소프트웨어 모듈은 통상 **보안수준 1**을 목표로 한다.)

19790에서 요구하는, 본 작업에 직결되는 항목:

| 영역 | 요구사항 | BoringSSL FIPS 인프라 대응 |
|---|---|---|
| 암호경계(Cryptographic Boundary) | 모듈 코드/데이터 범위를 명확히 정의 | `crypto/fipsmodule/bcm.cc` 단일 빌드 단위 (`BORINGSSL_bcm_text_start/end`) |
| 승인된 동작모드 | 승인 알고리즘만 사용하는 모드 표시 | `service_indicator` 메커니즘 |
| 가동 전 자가시험 | 무결성 시험 + 알고리즘 KAT | `self_check/self_check.cc.inc`, 모듈 HMAC-SHA256 무결성 |
| 조건부 자가시험 | 키쌍 일치시험(PCT), 연속 RNG 시험 | RSA/ECDSA PCT, CTR-DRBG 시험 존재 |
| 핵심보안매개변수(CSP) 관리 | 키 생성/영점화(zeroization) | `OPENSSL_cleanse` 등 기존 메커니즘 |

### 1.1 KCMVP 검증대상 암호알고리즘 (KISA 고시)

| 분류 | 알고리즘 | BoringSSL 현황 |
|---|---|---|
| **블록암호** | ARIA, SEED, LEA, HIGHT, AES | AES만 존재 → **ARIA·SEED·LEA·HIGHT 신규** |
| **해시함수** | SHA-2(224/256/384/512), SHA-3(224/256/384/512), LSH(224/256/384/512/512-224/512-256) | SHA-2 ✓, SHA-3(Keccak)는 내부 존재(EVP 미노출), **LSH 신규** |
| **메시지인증(MAC)** | HMAC, CMAC, GMAC | HMAC ✓, CMAC ✓, GMAC(=GCM) ✓ — **국산 블록암호 기반으로 확장 필요** |
| **난수발생기(DRBG)** | Hash_DRBG, HMAC_DRBG, CTR_DRBG | CTR_DRBG(AES-256)만 존재 → **Hash_DRBG·HMAC_DRBG 신규** |
| **공개키 암호** | RSAES | ✓ (RSA) |
| **전자서명** | RSA-PSS, KCDSA, EC-KCDSA, ECDSA | RSA-PSS ✓, ECDSA ✓ → **KCDSA·EC-KCDSA 신규** |
| **키 설정** | DH, ECDH | ✓ |
| **키 유도(KDF)** | KBKDF(HMAC/CMAC 기반), PBKDF(HMAC 기반) | PBKDF2 ✓, HKDF ✓ → **KBKDF(SP800-108 류) 신규** |

> 참고: KISA가 배포하는 **국산 알고리즘 참조 소스코드**(ARIA/SEED/LEA/HIGHT/LSH/KCDSA C 구현)를 기반으로 이식하면 정확성·검증 효율이 높다. (`seed.kisa.or.kr` 자료실)

### 1.2 GAP 요약 — 신규 구현이 필요한 항목

1. 블록암호: **ARIA, SEED, LEA, HIGHT** (+ 운영모드 ECB/CBC/CTR/GCM/CCM)
2. 해시: **LSH** 전체 변형, **SHA-3** EVP 노출
3. DRBG: **Hash_DRBG, HMAC_DRBG**
4. 전자서명: **KCDSA, EC-KCDSA**
5. KDF: **KBKDF**
6. MAC/AEAD를 국산 블록암호 기반으로 확장(CMAC-ARIA, GCM-ARIA 등)
7. **자가시험/무결성/service indicator를 KCMVP 알고리즘 포함하도록 확장**, FIPS 명칭을 KCMVP 모드로 정리
8. Rust 바인딩(boring) 신규 알고리즘 노출

---

## 2. 아키텍처 결정

### 2.1 FIPS 인프라 재사용 (재발명 금지)
BoringSSL의 `BORINGSSL_FIPS` 빌드 경로를 KCMVP 모듈 빌드의 토대로 삼는다.
- **암호경계** = `crypto/fipsmodule/bcm.cc` 단일 컴파일 단위. 신규 국산 알고리즘은 모두 `crypto/fipsmodule/` 하위에 `*.cc.inc`로 넣고 `bcm.cc`에 include하여 경계 안에 둔다.
- **무결성 검사** = 모듈 텍스트/로데이터에 대한 HMAC-SHA256 (delocate / `fips_shared.lds` 기반). KCMVP도 동일하게 SHA-256 기반 무결성 시험을 인정하므로 그대로 사용.
- **가동 전 자가시험** = `self_check.cc.inc`의 KAT 프레임워크를 그대로 쓰고 국산 알고리즘 KAT를 추가.
- **승인 모드 표시** = `service_indicator`에 국산 알고리즘 승인 판정을 추가.

### 2.2 빌드 플래그/네이밍 전략
- 신규 Cargo feature `kcmvp`를 추가하거나, 기존 `fips` feature 경로를 재사용한다. **권장: 별도 `kcmvp` feature**를 만들어 `BORING_BSSL_KCMVP_SOURCE_PATH` 등 환경변수를 분리(`boring-sys/build/config.rs`).
- C 측은 새 매크로 `BORINGSSL_KCMVP`(= `BORINGSSL_FIPS` 인프라 + 국산 알고리즘 활성)로 게이팅.
- 현재 submodule은 이미 `zeronsoftn/korecrypto.git`(`.gitmodules`)을 가리키므로 C 변경은 그 fork에서 진행한다.

### 2.3 승인 모드 정책
- 승인 모드에서는 KCMVP 검증대상 알고리즘만 호출되도록 service indicator로 추적·노출하고, Rust 측에 `kcmvp::approved()` 류 질의 API를 제공.
- 비승인(legacy) 알고리즘(MD5, RC4, DES 등)은 빌드에서 제외하거나 비승인 경로로 명확히 분리.

---

## 3. 단계별 구현 계획

### Phase 0 — 기반 정비 (빌드/CI/하네스)
- [ ] `boring-sys/build/config.rs`·`main.rs`에 `kcmvp` feature 및 `BORING_BSSL_KCMVP_*` 환경변수 추가. cmake 플래그 `-DKCMVP=1`(내부적으로 FIPS 인프라 on) 정의.
- [ ] `boring/Cargo.toml`·`boring-sys/Cargo.toml`에 `kcmvp` feature 와이어링.
- [ ] BoringSSL `CMakeLists.txt`/`build.json`에 국산 알고리즘 소스가 `bcm` 타깃에 포함되도록 빌드 목록 등록.
- [ ] bindgen allowlist(`boring-sys/build/main.rs`)에 신규 심볼(`EVP_aria_*`, `EVP_lsh*`, `KCDSA_*` 등) 추가.
- [ ] 국산 알고리즘 KAT 벡터 확보(KISA 시험벡터/표준문서) 및 `crypto/fipsmodule/.../test` 정비.

### Phase 1 — 국산 블록암호 (ARIA·SEED·LEA·HIGHT)
대상 파일(신규): `crypto/fipsmodule/{aria,seed,lea,hight}/`
- [ ] 코어 구현(`aria.cc.inc` 등): 키 스케줄 + 블록 암/복호. KISA 참조코드 이식, 상수시간/정렬 점검.
- [ ] 내부 인터페이스를 `bcm_interface.h`에 선언(`BCM_aria_encrypt` 등), `bcm.cc`에 include.
- [ ] 운영모드 결합: 기존 `cipher/` 모드 루틴(CBC/CTR/GCM/CCM)에 블록함수 포인터로 연결.
- [ ] `EVP_CIPHER` 정의: `crypto/fipsmodule/cipher/e_aria.cc.inc` 등에서 `DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aria_128_cbc)` 패턴으로 ECB/CBC/CTR/GCM(+CCM) 변형 작성 (참조: `e_aes.cc.inc`).
- [ ] NID 등록: `crypto/obj`(OID/NID 테이블) + `include/openssl/nid.h`에 `NID_aria_128_cbc` 등 추가.
- [ ] 이름/NID 룩업 등록: `crypto/cipher/get_cipher.cc` `kCiphers[]`.
- [ ] 헤더 노출: `include/openssl/cipher.h`(또는 신규 `aria.h`)에 `EVP_aria_*` 선언.
- 우선순위: **ARIA 최우선**(국산 표준·활용도 최다) → SEED → LEA → HIGHT.

### Phase 2 — 해시함수 (LSH, SHA-3 노출)
- [ ] LSH: `crypto/fipsmodule/lsh/lsh.cc.inc` 신규(LSH-256/512 코어 + 변형 출력). `bcm.cc` include.
- [ ] `EVP_MD` 정의: `digests.cc.inc` 패턴으로 `EVP_lsh256_256` 등, `DEFINE_METHOD_FUNCTION` 사용.
- [ ] SHA-3: BoringSSL `crypto/fipsmodule/keccak`가 이미 존재(ML-KEM/DSA용). 이를 `EVP_MD`(`EVP_sha3_256` 등)로 래핑하여 노출.
- [ ] NID/룩업 등록: `nid.h`, `digest/digest_extra.cc` `nid_to_digest_mapping[]`.

### Phase 3 — MAC / DRBG
- [ ] CMAC/GMAC를 국산 블록암호로 확장(CMAC-ARIA 등): 기존 `fipsmodule/cmac`, GCM 모드가 블록함수에 일반화되어 있으므로 cipher 등록만 추가.
- [ ] **Hash_DRBG**(`crypto/fipsmodule/rand/hash_drbg.cc.inc`): SP800-90A 해시 기반 DRBG 신규.
- [ ] **HMAC_DRBG**(`.../hmac_drbg.cc.inc`): SP800-90A HMAC 기반 DRBG 신규.
- [ ] 기존 `rand`의 진입점에서 모듈 기본 RNG는 CTR_DRBG 유지하되, KCMVP용 Hash/HMAC_DRBG 인스턴스 API 제공 및 연속시험(continuous test) 적용.

### Phase 4 — 전자서명 (KCDSA, EC-KCDSA)
- [x] **KCDSA**(`crypto/fipsmodule/kcdsa/kcdsa.cc.inc`, `include/openssl/kcdsa.h`): 도메인 파라미터(P/Q/G), 키생성(y=G^{x^{-1} mod Q} mod P), 서명/검증. BoringSSL BIGNUM 재사용, 해시 SHA-224/256. Rust `boring/src/kcdsa.rs` + KISA 참조구현 교차검증 KAT(P=2048,Q=224,SHA-224).
- [x] **EC-KCDSA**(`crypto/fipsmodule/eckcdsa/eckcdsa.cc.inc`, `include/openssl/eckcdsa.h`): 기존 `ec`/`bn` 인프라 재사용(NIST P-224/P-256), 공개키 Q=d^{-1}·G. Rust `boring/src/eckcdsa.rs` + KISA 참조구현 교차검증 KAT(P-224/SHA-224).
- [x] 키 생성 + 키쌍 일치시험(PCT): `EC_KCDSA_KEY_generate`/`KCDSA_KEY_generate` — 무작위 개인키(BN_rand_range_ex) 생성 후 PCT(서명→검증) 수행, 실패 시 키 폐기. Rust `generate()`.
- [x] 추가 KAT: EC-KCDSA P-256/SHA-256, KCDSA Q=256/SHA-256 (KISA 참조 교차검증). 키생성+PCT 왕복 시험.
- [ ] (후속) `EVP_PKEY` 통합: 현재는 DRBG/KBKDF와 동일하게 독립 함수 API로 노출. 필요 시 `EVP_PKEY_KCDSA` 타입/`pkey_method`, ASN.1 인코딩, NID/OID 등록.

### Phase 5 — KDF (KBKDF)
- [ ] **KBKDF**(SP800-108, Counter/Feedback 모드, HMAC·CMAC 기반): `crypto/fipsmodule/kdf/kbkdf.cc.inc` 신규.
- [ ] PBKDF2(`crypto/pkcs8`/`pkcs5`)는 존재 — KCMVP 승인 파라미터(반복수/해시) 검토만.
- [ ] EVP KDF 또는 전용 함수로 노출.

### Phase 6 — 자가시험 · 무결성 · 승인모드 (KCMVP 핵심)
- [ ] `self_check.cc.inc`에 신규 알고리즘 **KAT 추가**: ARIA/SEED/LEA/HIGHT(각 모드), LSH, SHA-3, Hash/HMAC_DRBG, KCDSA/EC-KCDSA 서명검증, KBKDF. (KISA 표준 시험벡터 사용)
- [ ] 무결성 검사: 신규 코드가 모두 `bcm.cc` 경계 안에 들어가 모듈 해시에 포함되는지 확인(delocate/`fips_shared.lds` 점검). `util/fipstools`로 무결성 해시 주입 절차 검증.
- [ ] `service_indicator`: 국산 알고리즘 승인 판정 추가(`EVP_Cipher_verify_service_indicator`, `EVP_DigestSign_verify_service_indicator` 등 분기 확장).
- [ ] 가동 전 자가시험 실패 시 모듈 사용 불가(오류상태) 동작 확인. `BORINGSSL_self_test` 진입점/`FIPS_mode()` 의미를 KCMVP 모드로 정리.
- [ ] CSP 영점화 경로 점검(키/DRBG 상태 `OPENSSL_cleanse`).

### Phase 7 — Rust 바인딩 (boring)
- [ ] `boring/src/symm.rs`: `Cipher::aria_128_cbc()`, `seed_cbc()`, `lea_*()`, `hight_*()` 등 생성자 추가.
- [ ] `boring/src/aead.rs`: `Algorithm::aria_128_gcm()` 등.
- [ ] `boring/src/hash.rs`·`sha.rs`: `MessageDigest::lsh256_256()`, `sha3_256()` 등.
- [ ] 신규 모듈 `boring/src/kcdsa.rs`(서명), `boring/src/kdf.rs`(KBKDF), DRBG 노출.
- [ ] `boring/src/fips.rs` → `kcmvp.rs`로 정리: `kcmvp::enabled()`, `kcmvp::approved()`(service indicator 질의), 자가시험 트리거 API.
- [ ] `lib.rs` 모듈 등록 및 `cfg(feature="kcmvp")` 게이팅, 단위테스트(KAT) 추가.

### Phase 8 — 문서 · 시험 · 제출 준비
- [ ] **암호모듈 보안정책서(Security Policy)** 작성: 암호경계, 승인 알고리즘, 역할/서비스, 자가시험, 키관리(19790 부속서 양식).
- [ ] 알고리즘 자가시험 결과·시험벡터 정리, 시험기관 제출용 산출물.
- [ ] 비승인 알고리즘 제거/격리 확인, 빌드 산출물 재현성(reproducible build) 확보.
- [ ] 전체 회귀 테스트(`boring/test`, BoringSSL `crypto_test`) 및 KAT 통과 확인.

---

## 4. 변경 위치 빠른 참조 (concrete touch points)

| 작업 | 파일 |
|---|---|
| feature/빌드 | `boring-sys/build/config.rs`, `boring-sys/build/main.rs`, `boring*/Cargo.toml` |
| 암호경계 포함 | `crypto/fipsmodule/bcm.cc` (신규 `.cc.inc` include) |
| 신규 알고리즘 코어 | `crypto/fipsmodule/{aria,seed,lea,hight,lsh,kcdsa,ec_kcdsa,rand,kdf}/...` |
| 내부 선언 | `crypto/fipsmodule/bcm_interface.h` |
| EVP_CIPHER 정의 | `crypto/fipsmodule/cipher/e_aria.cc.inc` 등 (참조: `e_aes.cc.inc`) |
| EVP_MD 정의 | `crypto/fipsmodule/digest/digests.cc.inc` |
| 이름/NID 룩업 | `crypto/cipher/get_cipher.cc`, `crypto/digest/digest_extra.cc` |
| NID/OID | `include/openssl/nid.h`, `crypto/obj/*` |
| 헤더 노출 | `include/openssl/{cipher,digest,evp,...}.h` |
| 자가시험 KAT | `crypto/fipsmodule/self_check/self_check.cc.inc` |
| 승인모드 | `crypto/fipsmodule/service_indicator/service_indicator.cc.inc` |
| Rust 노출 | `boring/src/{symm,aead,hash,sha,kcdsa,kdf,kcmvp}.rs`, `boring/src/lib.rs` |

---

## 5. 위험요소 및 고려사항

- **알고리즘 정확성**: KISA 표준 시험벡터로 KAT를 반드시 통과시켜야 함. 참조코드 이식 시 엔디안/패딩/키스케줄 오류 주의.
- **암호경계 무결성**: 신규 코드가 `bcm.cc` 외부(예: `crypto/aria/`)에 위치하면 모듈 해시에서 빠져 무결성 검사 누락 → 반드시 `fipsmodule/` 내부 + `bcm.cc` include.
- **delocate/어셈블리**: 국산 알고리즘에 asm 최적화를 넣으면 delocate 처리 대상이 됨. 초기엔 순수 C로 구현해 무결성 빌드 복잡도 최소화.
- **상위 토론**: BoringSSL FIPS 버전은 특정 컴파일러(clang)·고정 소스 스냅샷에 묶임. KCMVP 모듈 버전 고정 및 재현 빌드 필요.
- **TLS 연동(선택)**: KCMVP 암호스위트(ARIA-GCM 등)를 TLS에 노출할지는 범위 결정 필요. 1차 범위는 crypto 모듈로 한정 권장.
- **유지보수**: upstream BoringSSL 머지 시 국산 알고리즘/자가시험 충돌 관리(현 fork `korecrypto` 기준).

---

## 6. 권장 진행 순서 (마일스톤)

1. **M1** ✅: Phase 0 + ARIA(전 모드) + KAT + Rust 노출 — *수직 슬라이스로 전 파이프라인 검증*.
2. **M2** ✅: SEED·LEA·HIGHT, LSH·SHA-3.
3. **M3** ✅: Hash/HMAC_DRBG, KBKDF (CMAC/GMAC는 기존 보유).
4. **M4** ✅(코어): KCDSA·EC-KCDSA 서명/검증 + KISA 참조 교차검증 KAT. (PCT/EVP_PKEY 통합은 후속.)
5. **M5**: 자가시험/무결성/승인모드 완성, 보안정책서, 시험기관 제출 산출물.

> M1을 먼저 끝내 빌드→경계→자가시험→Rust 노출의 전 과정을 한 알고리즘으로 검증한 뒤 나머지를 수평 확장하는 것을 강력 권장.
