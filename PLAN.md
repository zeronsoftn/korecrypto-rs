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

### 1.2 GAP 요약 — 신규 구현이 필요한 항목 (진행현황)

1. [x] 블록암호: **ARIA, SEED, LEA, HIGHT** (+ 운영모드 ECB/CBC/CTR/GCM/CCM)
2. [x] 해시: **LSH** 전체 변형, **SHA-3** EVP 노출
3. [x] DRBG: **Hash_DRBG, HMAC_DRBG**
4. [x] 전자서명: **KCDSA, EC-KCDSA** (서명/검증/키생성/PCT)
5. [x] KDF: **KBKDF** (HMAC counter/feedback)
6. [~] MAC/AEAD 국산 블록암호 확장: GCM/CCM-ARIA·LEA·SEED 동작. CMAC-ARIA 등 별도 등록은 후속.
7. [ ] **자가시험/무결성/service indicator를 KCMVP 알고리즘 포함하도록 확장**, FIPS 명칭을 KCMVP 모드로 정리 — **미착수(M5)**
8. [x] Rust 바인딩(boring) 신규 알고리즘 노출

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
- [ ] (미적용/설계변경) `kcmvp` feature 게이팅: 현재는 국산 알고리즘을 **항상 컴파일**하므로 별도 feature/`BORING_BSSL_KCMVP_*` 환경변수·`-DKCMVP=1` 플래그를 두지 않았다. 승인모드(M5)에서 런타임 정책으로 다룰 예정.
- [ ] (미적용/설계변경) `Cargo.toml` `kcmvp` feature 와이어링 — 위와 동일 사유로 보류.
- [x] BoringSSL 빌드 목록 등록: 신규 `.cc.inc`/헤더를 `gen/sources.cmake` 의 `bcm` 소스 및 헤더 목록에 추가, `bcm.cc` 에서 include.
- [x] bindgen: BoringSSL bindgen에는 allowlist 필터가 없다. 독립 헤더는 `boring-sys/build/main.rs` 의 `must_have_headers` 목록에 추가해야 심볼이 바인딩된다(`aria.h`, `lea.h`, `seed.h`, `hight.h`, `lsh.h`, `kbkdf.h`, `drbg_kcmvp.h`, `eckcdsa.h`, `kcdsa.h` 등록 완료).
- [x] 국산 알고리즘 KAT 벡터 확보: KISA 참조소스(samples/) 또는 RFC/NIST/표준 벡터로 알고리즘별 확보, Rust 단위테스트로 정비.

### Phase 1 — 국산 블록암호 (ARIA·SEED·LEA·HIGHT) ✅
신규 파일: `crypto/fipsmodule/{aria,seed,lea,hight}/<c>.cc.inc` (코어) + `crypto/fipsmodule/cipher/e_<c>.cc.inc` (EVP/AEAD)
- [x] 코어 구현: 키 스케줄 + 블록 암/복호. KISA 참조 이식, 명시적 빅엔디안 로드(엔디안 이슈 회피).
- [x] 운영모드 결합: CBC/CTR/GCM/CCM 을 블록함수 포인터로 연결(GCM=CRYPTO_ghash_init+CTR, CCM=AES CCM128 헬퍼 재사용).
- [x] `EVP_CIPHER` 정의: `DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aria_128_cbc)` 패턴으로 ECB/CBC/CTR/GCM. CCM 은 EVP_AEAD(seal_scatter/open_gather)로 노출. HIGHT 는 64비트 블록이라 ECB/CBC/CTR 만.
- [x] NID 등록: `include/openssl/nid.h` (ARIA 1065-1079/1124-1126 OpenSSL 호환, LEA 2001-2012, SEED 2101-2104, HIGHT 2105-2107).
- [~] 이름/NID 룩업(`get_cipher.cc kCiphers[]`)은 등록하지 않음 — `EVP_*` 게터 + Rust `Cipher` 생성자로 직접 노출하므로 문자열 룩업은 불필요(필요 시 후속).
- [x] 헤더 노출: 신규 `include/openssl/{aria,lea,seed,hight}.h`, AEAD 게터는 `aead.h`.
- 비고: 별도 `bcm_interface.h` 선언 대신 공개 헤더 + `bcm.cc` include 방식 사용.

### Phase 2 — 해시함수 (LSH, SHA-3 노출) ✅
- [x] LSH: `crypto/fipsmodule/lsh/lsh.cc.inc` 신규(LSH-256/512 코어, 스텝 상수 사전계산). `bcm.cc` include. NID 2201-2206.
- [x] `EVP_MD` 정의: `EVP_lsh256_{224,256}`, `EVP_lsh512_{224,256,384,512}`. (`EVP_MAX_MD_DATA_SIZE` 208→416 상향: LSH-512 상태 수용.)
- [x] SHA-3: BCM Keccak 코어에 224/384 config 추가 후 `EVP_sha3_{224,256,384,512}` 로 래핑 노출. NID 1096-1099.
- [x] Rust 노출: `MessageDigest::lsh*`, `sha3_*` (hash.rs). 검증: KISA python 참조(LSH), FIPS 202(SHA-3).

### Phase 3 — MAC / DRBG
- [~] CMAC/GMAC 국산 블록암호 확장: ARIA-GCM/GMAC 동작(코어). CMAC-ARIA 등 별도 등록은 후속.
- [x] **Hash_DRBG**(`crypto/fipsmodule/rand/drbg90a.cc.inc`): SP800-90A 해시 기반 DRBG. (별도 파일 대신 drbg90a 에 통합.)
- [x] **HMAC_DRBG**(동 파일): SP800-90A HMAC 기반 DRBG. EVP_MD 파라미터화. Rust `boring/src/drbg.rs` + NIST CAVP KAT.
- [ ] (후속) 모듈 기본 RNG(CTR_DRBG) 유지 + Hash/HMAC_DRBG 인스턴스에 연속시험(continuous test) 적용은 미구현. caller 가 엔트로피/논스 공급.

### Phase 4 — 전자서명 (KCDSA, EC-KCDSA)
- [x] **KCDSA**(`crypto/fipsmodule/kcdsa/kcdsa.cc.inc`, `include/openssl/kcdsa.h`): 도메인 파라미터(P/Q/G), 키생성(y=G^{x^{-1} mod Q} mod P), 서명/검증. BoringSSL BIGNUM 재사용, 해시 SHA-224/256. Rust `boring/src/kcdsa.rs` + KISA 참조구현 교차검증 KAT(P=2048,Q=224,SHA-224).
- [x] **KCDSA 도메인 파라미터 생성(PQG)**: `KCDSA_generate_parameters`(+`kcdsa_ppgf`) — TTAK.KO-12.0001 절차로 Seed→J→Q→P(=2JQ+1) 소수쌍·생성원 G=h^{2J} mod P 생성, 증거값 Seed/Count/J/h 반환. P/Q/G·x getter 추가. Rust `generate_parameters`/`params`/`private_key`/`public_key`. PPGF 는 공식 KCDSA 샘플(samples/cavp/KCDSA)의 J/Q/P 와 일치 검증.
- [x] **EC-KCDSA**(`crypto/fipsmodule/eckcdsa/eckcdsa.cc.inc`, `include/openssl/eckcdsa.h`): 기존 `ec`/`bn` 인프라 재사용(NIST P-224/P-256), 공개키 Q=d^{-1}·G. Rust `boring/src/eckcdsa.rs` + KISA 참조구현 교차검증 KAT(P-224/SHA-224).
- [x] 키 생성 + 키쌍 일치시험(PCT): `EC_KCDSA_KEY_generate`/`KCDSA_KEY_generate` — 무작위 개인키(BN_rand_range_ex) 생성 후 PCT(서명→검증) 수행, 실패 시 키 폐기. Rust `generate()`.
- [x] 추가 KAT: EC-KCDSA P-256/SHA-256, KCDSA Q=256/SHA-256 (KISA 참조 교차검증). 키생성+PCT 왕복 시험.
- [ ] (후속) `EVP_PKEY` 통합: 현재는 DRBG/KBKDF와 동일하게 독립 함수 API로 노출. 필요 시 `EVP_PKEY_KCDSA` 타입/`pkey_method`, ASN.1 인코딩, NID/OID 등록.
- [x] **KCDSA CAVP(.rsp) 전 시험유형 동작**: KPG/SGT/SVT 모두 cavp-test 하네스에서 생성·검증된다. KPG/SGT 는 위 PQG 생성기로 도메인 파라미터+키쌍을 만들어 채운다. 검증 근거: 공식 검증시스템 문서(`samples/KCDSA_검증시스템.pdf`, KCDSAVS V3.0) §4.1·§5.2 에 따르면 KCDSAVS 는 X 를 시드로 재현하지 않고 (P,Q)소수·구조, G 위수, 0<X<Q, Y 일관성만 검사한다. DH PGT/PVT 도 같은 PQG/판정 로직으로 동작(`cavp-test/src/dh.rs`).
- [보류] **EC-KCDSA CAVP 일부 보류**: ① 이진체 곡선(B/K-233/283, BoringSSL이 GF(2ⁿ) 곡선 미지원)은 미지원. 소수체 P-224/256 의 KPG/PKV/SGT/SVT(곡선≠해시 R 절단 포함)는 동작한다.

### Phase 5 — KDF (KBKDF)
- [x] **KBKDF**(SP800-108): `crypto/fipsmodule/kdf/kbkdf.cc.inc` — HMAC Counter/Feedback 모드. KISA 인코딩 준수. 검증: KISA KBKDF-HMAC-SHA256 벡터. (CMAC 기반·이중 파이프라인 모드는 후속.)
- [x] PBKDF2(`crypto/pkcs5`)는 기존 보유 — 별도 구현 불요.
- [x] 전용 함수 + Rust `boring/src/kdf.rs` 로 노출.

### Phase 6 — 자가시험 · 무결성 · 승인모드 (KCMVP 핵심)
- [ ] `self_check.cc.inc`에 신규 알고리즘 **KAT 추가**: ARIA/SEED/LEA/HIGHT(각 모드), LSH, SHA-3, Hash/HMAC_DRBG, KCDSA/EC-KCDSA 서명검증, KBKDF. (KISA 표준 시험벡터 사용)
- [ ] 무결성 검사: 신규 코드가 모두 `bcm.cc` 경계 안에 들어가 모듈 해시에 포함되는지 확인(delocate/`fips_shared.lds` 점검). `util/fipstools`로 무결성 해시 주입 절차 검증.
- [ ] `service_indicator`: 국산 알고리즘 승인 판정 추가(`EVP_Cipher_verify_service_indicator`, `EVP_DigestSign_verify_service_indicator` 등 분기 확장).
- [ ] 가동 전 자가시험 실패 시 모듈 사용 불가(오류상태) 동작 확인. `BORINGSSL_self_test` 진입점/`FIPS_mode()` 의미를 KCMVP 모드로 정리.
- [ ] CSP 영점화 경로 점검(키/DRBG 상태 `OPENSSL_cleanse`).

### Phase 7 — Rust 바인딩 (boring) ✅(대부분)
- [x] `boring/src/symm.rs`: `Cipher::aria_128_cbc()`, `seed_cbc()`, `lea_*()`, `hight_*()` 등 생성자.
- [x] `boring/src/aead.rs`: `Algorithm::aria_128_ccm()`, `lea_128_ccm()`, `seed_ccm()` 등.
- [x] `boring/src/hash.rs`: `MessageDigest::lsh256_256()`, `sha3_256()` 등.
- [x] 신규 모듈 `boring/src/{kcdsa,eckcdsa,kdf,drbg}.rs` 노출 + KAT.
- [ ] (후속) `boring/src/fips.rs` → `kcmvp.rs` 정리: `kcmvp::enabled()`/`approved()`(service indicator 질의), 자가시험 트리거 API.
- [x] `lib.rs` 모듈 등록 및 단위테스트(KAT). (`cfg(feature="kcmvp")` 게이팅은 항상-on 설계로 미적용.)

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
| 신규 알고리즘 코어 | `crypto/fipsmodule/{aria,seed,lea,hight,lsh,keccak,kcdsa,eckcdsa,rand,kdf}/...` |
| 빌드 소스/헤더 목록 | `gen/sources.cmake`, `boring-sys/build/main.rs` (`must_have_headers`) |
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
4. **M4** ✅: KCDSA·EC-KCDSA 서명/검증/키생성 + PCT + KISA 참조 교차검증 KAT(P-224/256, Q-224/256). (EVP_PKEY 통합은 후속.)
5. **M5** (다음 단계): 자가시험/무결성/승인모드 완성, 보안정책서, 시험기관 제출 산출물.

> 현황 요약: M1~M4 완료. **모든 KCMVP 검증대상 알고리즘의 코어 구현 + Rust 노출 + KAT 완료**.
> 남은 핵심은 M5(가동 전 자가시험 KAT 등록·무결성·승인모드·문서)와, 선택적 후속(EVP_PKEY 통합, DRBG 연속시험, KBKDF-CMAC, kcmvp feature 게이팅).

---

## 7. Windows 크로스컴파일 FIPS 빌드 지원 (clang, COFF) ✅

목표: 리눅스 호스트에서 clang(`x86_64-w64-windows-gnu`)으로 **FIPS 모드 crypto 라이브러리**를 크로스컴파일. 진입점은 `boring-sys/deps/boringssl/Makefile` 의 `build-windows` 타깃 (`rm -rf build-windows && make build-windows`).

핵심 난점: BoringSSL FIPS 무결성 인프라(`delocate`, `inject_hash`, 모듈 경계 심볼)가 **ELF/Mach-O 전용**이었음. 윈도우 대상은 **COFF/PE** 어셈블리(COMDAT `.text$`, `.rdata`, SEH, `.refptr`, `.def`)를 생성해 그대로는 처리 불가.

수행한 작업:

- **delocate COFF 포팅 + 파일 분리**: `util/fipstools/delocate/` 를 `delocate.go`(공통 + `objectFormat` 자동판별/디스패치), `delocate_elf.go`(기존 ELF/Mach-O 로직 그대로), `delocate_coff.go`(신규)로 분리. COFF 처리: `.text$*`/`.rdata`→`.text` 평탄화, 내부 전역참조→`.L..._local_target`(COMDAT 병합 방지), 외부 call/jmp→redirector 썽크(`jmp X` 또는 `jmp *__imp_X(%rip)`), 외부 주소적재(`leaq`)→모듈 밖 포인터(`bcm_external_X`), `.refptr.X`→직접 `leaq`. 결과: 해시 대상 영역 `[bcm_text_start, bcm_text_end)` 에 **재배치 0개** 보장(꼬리에만 재배치 존재).
- **inject_hash COFF 포팅**: `debug/pe` 로 COFF 오브젝트 파싱(`hashModuleCOFF`). COFF 영역이 재배치-프리이므로 정적 오브젝트에서 직접 해시 계산(별도 링크 모듈 불필요).
- **스레드 모델**: MinGW FIPS 빌드에서 winpthreads 의 `PTHREAD_RWLOCK_INITIALIZER == -1` 때문에 정적 락이 `.data` 로 배치되는 문제 → `OPENSSL_WINDOWS_THREADS`(SRWLOCK, 0초기화) 강제([crypto/internal.h]). 동반 수정: `WIN32_LEAN_AND_MEAN`(winsock 순서), `thread_win.cc` TLS 종료 콜백을 MinGW(`.CRT$XLC` section/used 속성)로 이식.
- **소스 가드**: `bcm.cc`(sys/mman.h, PROT_* 매크로), 지터 엔트로피 소스(`entropy/jitter.cc.inc`, `entropy/internal.h`)를 윈도우에서 활성화(x86_64 는 `_rdtsc()` 사용).
- **빌드 설정**: `Makefile build-windows` 에 `-DBUILD_TESTING=OFF`(크로스컴파일 시 benchmark configure 실패 회피), `-DOPENSSL_NO_ASM=1`(윈도우용 GAS-COFF perlasm 부재 + NASM 은 delocate 비호환 → 순수 C 구현 사용). 툴체인(`util/clang-toolchain.cmake`)에 ASM 타깃 추가. `CMakeLists.txt` FIPS_DELOCATE 경로에 COFF 분기(타깃 트리플로 판별).

- **링크 가능성(COMDAT weak)**: delocate 가 COMDAT `.text$X,...,discard,X` 를 단일 `.text` 로 평탄화하면 인라인/템플릿 심볼이 강한 전역이 되어 다른 번역단위의 COMDAT 사본과 **중복 심볼** 충돌(실제 exe 링크 시 발생) → delocate_coff.go 에서 해당 심볼을 `.weak` 로 출력해 해결(원래 COMDAT dedup 의도 복원).

검증(두 가지 독립 방법, `Makefile` 의 `make check-windows`):
1. **wine 실행 테스트** (`test-windows`): `fipstest/fips_selftest.c` 를 `libcrypto.a` 와 정적 링크(`clang++ --target=... -static -static-libstdc++ -static-libgcc`)해 exe 생성 후 `wine` 실행 → bcm 생성자 무결성 검사 통과 + `BORINGSSL_integrity_test()==1` → `FIPS INTEGRITY: PASS`.
2. **정적 해시 검사** (`verify-hash-windows`): `llvm-nm`/`llvm-objcopy` 로 `bcm.o` 의 text start/end/hash 와 `.text` 바이트를 뽑아 `HMAC-SHA256(키=0, text[start:end])` 를 재계산 → 주입된 해시와 **일치** 확인.

그 외: `make build-windows` 성공 → `libcrypto.a`(COFF) 생성, `bcm.o` 해시 주입 완료, 해시영역 재배치 0개. ELF delocate 단위테스트 통과(기존 동작 보존).

### 7.1 asm 최적화 활성화 (OPENSSL_NO_ASM 제거, asm 을 FIPS 모듈 안에) ✅

`OPENSSL_NO_ASM` 을 제거하고 x86_64 asm 최적화를 켰다. 단, delocate 가 GAS 만
파싱하므로(NASM/MASM/llvm-ml 불가) asm 은 perlasm 의 **mingw64**(GAS-COFF) flavour
로 생성해 delocate 가 **FIPS 모듈(무결성 경계) 안에** 접어 넣도록 했다. clang 이
GAS 를 조립하므로 llvm-ml 은 불필요.

- **perlasm 되살리기** (`crypto/perlasm/x86_64-xlate.pl`): `die "mingw64 not supported"` 제거, win64 타깃 가드(`defined(_WIN32)`) 추가, 섹션 시작 asm-local 레이블 금지(die)를 macOS(`.subsections_via_symbols`) 전용으로 한정, mingw64 에서 ELF `.hidden` 출력 억제.
- **SEH 핸들러 중복 해결**(COFF 전용 문제, **자동화됨**): COFF 는 함수마다 SEH unwind(`.pdata`/`.xdata`)와 예외 핸들러 함수가 필요한데, perlasm 이 파일별 static 핸들러를 generic 이름(`se_handler`, `mul_handler`, `sqr_handler` 등)으로 낸다. delocate 가 모듈 asm 을 하나로 병합하면 같은 이름이 충돌. 
  - **원래 방법** (수동): `.pl` 파일에서 핸들러 이름을 파일별로 개명(vpaes_se_handler, mont_mul_handler 등).
  - **현재 방법** (자동화): delocate 가 COFF 처리 중에 `*_handler` 패턴의 심볼을 감지하여 자동으로 파일별 유일 이름(`<symbol>_BCM_<fileindex>`)으로 개명. pl 파일 수정 불필요.
- **delocate 자동 심볼 개명**: 
  - `shouldRenameCOFFSymbol()`: `*_handler` 패턴 감지.
  - `mapCOFFSymbol()`: 파일별로 유일한 이름 생성.
  - `.def` 지시자, 라벨 정의, `.type`, `.size`, `.rva`/`.secrel32`/`.secidx` 참조 모두에서 개명 적용.
  - `.L` 로컬 레이블도 파일별 개명(`_BCM_n`)하여 SEH 데이터가 참조하는 함수 레이블과 일관성 유지.
  - ELF 은 `.cfi` 메타데이터만 쓰고 이런 핸들러 심볼이 없어 영향 없음.
- **빌드 연결**: 16개 x86_64 BCM asm(rsaz-avx2 포함) + 4개 crypto asm 을 mingw64 GAS 로 생성해 `gen/sources.cmake` 의 `BCM_SOURCES_ASM`/`CRYPTO_SOURCES_ASM` 에 추가(`#if defined(_WIN32)` 가드라 비윈도우 빌드엔 무영향).

검증(clean `make check-windows`): asm 함수(aes_hw_encrypt, gcm_ghash_clmul, rsaz_1024_mul_avx2, sha256_block_data_order_hw, vpaes_encrypt)가 **해시 모듈 안**에 위치, 해시영역 재배치 0개, 정적 해시 일치 + wine `FIPS INTEGRITY: PASS`. ELF delocate 단위테스트도 그대로 통과(ELF 무영향). 또한 `fips_selftest.c` 의 AES-256-CTR 속도 측정이 wine 에서 ~4.9 GiB/s 를 보여 AES-NI(asm)가 모듈 안에서 실제 동작함을 확인(순수 C 면 수백 MiB/s 수준).

> 한계: 무결성(integrity) 자가시험은 wine 런타임까지 통과 확인. **알고리즘 KAT(가동 전 자가시험 전체)** 의 윈도우 실측은 후속.

### 7.2 UEFI(x86_64) FIPS 빌드 지원 ✅

UEFI x86_64 도 **PE/COFF + MS x64 ABI** 이므로 윈도우용 COFF/FIPS 파이프라인이 그대로 적용된다. `make build-uefi` 로 빌드한다.

- **트리플 버그 우회**: clang 18.1.3 의 `x86_64-unknown-uefi` 는 데이터 레이아웃 불일치 버그(`m:w` vs `m:e`)로 trivial 코드도 컴파일 실패. 동작하는 COFF 트리플(`x86_64-w64-windows-gnu`, COFF·MS-ABI·mingw 헤더)을 사용한다.
- **UEFI 코드젠 플래그**: `-mno-red-zone`(펌웨어 인터럽트가 red zone 을 덮어쓸 수 있어 필수) + `-fno-stack-protector`. 초기 부팅에서 SSE/AVX 가 비활성일 수 있어 `OPENSSL_NO_ASM=1`(순수 C). (`-ffreestanding` 은 mingw 헤더가 bsearch 등을 숨겨 빌드를 깨므로 미사용 — 정적 라이브러리는 EFI 앱 링크 시 freestanding 으로 취급.)
- 검증(`make check-uefi`): COFF/FIPS 무결성 파이프라인 동일하게 동작 → 정적 해시 일치 + wine `FIPS INTEGRITY: PASS`(UEFI 빌드물도 COFF/MS-ABI 라 wine 에서 실행 가능).

> 참고: `build-linux` 타깃은 여전히 `x86_64-unknown-uefi`(구 clang 깨진 트리플)를 사용한다(이번 작업 범위 밖).

### 7.3 진짜 freestanding UEFI(`x86_64-unknown-uefi`, MSVC ABI) + libc++ 빌드 ✅

llvm-22 로 갱신하면 `x86_64-unknown-uefi` 가 동작한다(단, **MSVC C++ ABI**: 따옴표 맹글링 + `@feat.00` + CodeView). 이 타깃으로 hosted libc 없이 FIPS crypto 를 빌드한다.

- **libc 오버레이**(`util/uefi/overlay/`): ~~freestanding 에 없는 hosted 헤더를 선언만 제공~~ → **7.4 에서 picolibc 로 대체(오버레이 제거)**. CMakeLists 는 이제 `UEFI_OVERLAY` 대신 `PICOLIBC_INCLUDE` 캐시 변수로 외부 freestanding libc include 디렉터리를 받는다.
- **libc++/libc++abi**: `USE_CUSTOM_LIBCXX=1` → CMake 가 자동으로 llvm-project `llvmorg-22.1.8` 를 받아 `util/bot/libcxx{,abi}` 로 연결, 업스트림 블록이 UEFI 툴체인으로 함께 빌드. 핵심 설정: `__config_site` freestanding 화(스레드/로캘/iostream/와이드문자 off), `-D__LP64__=1`(libc++abi `__cxa_exception` 레이아웃), `-fno-exceptions`(이 타깃에서 clang-22 의 예외 코드젠 SIGSEGV 회피), `-fno-threadsafe-statics`, `_LIBCXXABI_HAS_NO_THREADS`; host 의존 소스(스레드/로캘/iostream/예외 personality·terminate·guard 등) 제외.
- **delocate MSVC 지원**: PEG 문법에 따옴표 심볼(`"?...@@"`)·`@`-심볼·CodeView 디렉티브(`.cv_*`) 추가(재생성). 따옴표 심볼의 local-target/redirector/accessor/external-ptr 이름은 따옴표 안쪽에 접두/접미를 넣어 파생(`decorateSymbol`), 디렉티브 재출력 시 재따옴표(`coffQuoteSymbol`). 외부 데이터 값 적재(`movq stderr(%rip),reg`)는 포인터 적재 후 역참조로 변환.
- **소스 가드**: 경계 심볼(BORINGSSL_bcm_text_*)을 `extern "C"` 로(=MSVC 비맹글링, delocate 합성과 일치); bcm.cc/rand 의 POSIX 헤더 UEFI 가드; 지터 엔트로피 UEFI 활성화.
- **엔트로피**: `crypto/rand/uefi.cc` — `CRYPTO_uefi_init(gBS)` 로 EFI Boot Services 를 받아 `EFI_RNG_PROTOCOL` 로 CRYPTO_sysrand 제공(`OPENSSL_RAND_UEFI`).

검증(`make build-uefi` → `make verify-hash-uefi`): COFF `libcrypto.a`/`bcm.o` 생성, 해시 주입 완료, **해시영역 재배치 0개**, 정적 해시 일치(calculated==injected). 런타임 자가시험은 wine 불가(MSVC freestanding) → 실제 UEFI(QEMU/OVMF)에서 별도 확인 필요.

### 7.4 libc 오버레이 → picolibc 전환 + cargo(`korecrypto-sys`) UEFI 빌드 ✅

7.3 의 번들 libc 선언 오버레이(`util/uefi/overlay/`)를 제거하고, **picolibc**([jc-lab/picolibc-rs](https://github.com/jc-lab/picolibc-rs)) 를 진짜 freestanding C 표준 라이브러리로 사용한다. cargo(`korecrypto-sys`) 경로에서 `x86_64-unknown-uefi` 로 FIPS crypto 를 빌드/링크하는 것까지 검증했다.

- **요구사항**: clang **>= 19**(clang 18 이하의 `x86_64-unknown-uefi` 데이터 레이아웃 버그 때문에 미지원). 기본 `clang` 이 18 이하면 `CC_x86_64-unknown-uefi`/`CXX_…`(예: clang-22)로 지정.
- **boringssl 측 변경**:
  - `util/uefi/overlay/` 삭제. CMakeLists 의 UEFI 블록은 `UEFI_OVERLAY`(번들) 대신 `PICOLIBC_INCLUDE` 캐시 변수(외부 freestanding libc include)를 `-isystem` 으로 추가하고, 미지정 시 `FATAL_ERROR`.
  - 공개 헤더 `base.h`: `__UEFI__` 가드 제거 — picolibc 가 `stdlib.h`/`sys/types.h` 를 공급하므로 다른 타깃과 동일하게 포함(bindgen 도 이 헤더를 uefi 타깃으로 파싱).
  - `target.h`/`Makefile` 의 오버레이 관련 주석을 picolibc 기준으로 갱신. `Makefile build-uefi` 는 `PICOLIBC_INCLUDE` 를 받도록 수정.
- **picolibc 연동**: picolibc 크레이트는 `links = "c"` 로 빌드한 헤더 디렉터리를 `DEP_C_INCLUDE` 로 노출 → `korecrypto-sys` build.rs 가 이를 `-DPICOLIBC_INCLUDE` 로 CMake 에 전달. picolibc 에는 malloc 이 없으므로 `malloc` feature 를 켜 Rust 전역 할당자에 위임(최종 바이너리가 `#[global_allocator]` 등록 필요).
- **`korecrypto-sys`(=boring-sys) 변경**:
  - 새 feature `picolibc`(optional dep `picolibc`, `features=["malloc"]`).
  - build.rs: uefi+picolibc 시 `OPENSSL_NO_ASM=1`, `USE_CUSTOM_LIBCXX=1`, `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY`, **`no_default_flags(true)`**(cmake-rs 가 주입하는 `--target=x86_64-unknown-windows-gnu` 를 막고 크로스컴파일 블록의 `CMAKE_*_COMPILER_TARGET=uefi` 가 트리플 결정 → `__UEFI__` 정의로 libc++ 가 Windows 경로 대신 `aligned_alloc` 사용). **crypto 만 빌드/링크**(ssl 은 소켓 등 OS 의존으로 제외). FIPS 컴파일러는 uefi 에서 `CC/CXX`(clang>=19) 사용. 번들 `libcxx`/`libcxxabi` 링크(`liblibcxx.a`/`liblibcxxabi.a`).
  - bindgen: uefi 타깃 인자(`--target` + `-I $DEP_C_INCLUDE`), 레이아웃 테스트 off(clang LLP64 vs Rust `c_long=i64` 불일치 회피).
  - lib.rs: **`#![no_std]`** + `core::ffi`, bindgen `use_core()`.
- **검증 하네스 `uefi-smoketest/`**(독립 워크스페이스): `uefi`(global_allocator) + picolibc(malloc) + `korecrypto-sys`(fips,picolibc). picolibc freestanding 스텁(write/read/lseek/close/_exit) + MS-ABI `__chkstk` no-op 제공. `CRYPTO_library_init`/`OPENSSL_malloc` 호출로 링크 강제.

검증 결과: `cargo build --target x86_64-unknown-uefi` 로 **PE32+ EFI application**(`uefi-smoketest.efi`, Subsystem `EFI_APPLICATION`) 생성 — boringssl crypto(FIPS) + picolibc(libc/libm+malloc) + libc++/libc++abi + no_std 크레이트가 끊김 없이 링크됨. 빌드 방법은 `uefi-smoketest/README.md` 참조.

> **ABI 주의**: clang 은 uefi 를 LLP64(`long`=4)로, Rust `core::ffi::c_long` 은 `i64`(8)로 보므로 `long` 을 쓰는 C API 는 UEFI 에서 FFI ABI 불일치 위험이 있다. crypto API 는 고정폭 타입 위주라 영향 없지만, `long` 기반 API 사용 시 주의.

### 7.5 번들 libc++/libc++abi 를 libcrypto.a 로 병합 (모체 libc++ 충돌 회피) ✅

bare-metal(picolibc) 빌드는 그동안 `libcrypto.a` 외에 `liblibcxx.a`/`liblibcxxabi.a` 를 따로 링크해야 했다. 모체 프로젝트가 libcrypto.a **하나만** 링크하면 되도록 번들 libc++/libc++abi 를 libcrypto.a 안으로 합치되, 모체가 자신의 libc++ 를 함께 쓰더라도 STL 심볼이 충돌하지 않게 한다.

구현은 **전부 boringssl 빌드(CMake) 안**에 둔다. libcrypto.a 는 boringssl 빌드의 산출물이므로, cargo(`korecrypto-sys`) 뿐 아니라 Makefile·외부 통합자 등 어떤 경로로 빌드해도 동일하게 self-contained libcrypto.a 가 나온다. (Rust build.rs 는 건드리지 않는다.)

- **충돌 회피 = ABI 네임스페이스 격리(포맷 비의존)**: libc++ 의 인라인 ABI 네임스페이스를 `std::__korecrypto` 로 바꿔 빌드한다. `CMakeLists.txt` 의 USE_CUSTOM_LIBCXX 블록에서 `add_compile_definitions(_LIBCPP_ABI_NAMESPACE=__korecrypto)`(디렉터리 전역) → 이후 정의되는 crypto/libcxx/libcxxabi 모든 C++ 타깃에 동일 적용되어 경계 너머 STL 참조가 일관되게 해소된다. 모체의 `std::__1` 과 맹글링이 갈라져 weak/COMDAT 폴딩 충돌이 없다. `BAREMETAL_LIBC_INCLUDE` 로 게이트해 upstream 의 hosted USE_CUSTOM_LIBCXX 테스트 빌드에는 영향이 없다. (기본값은 매크로 미정의 → 네임스페이스가 리터럴 토큰 `_LIBCPP_ABI_NAMESPACE` 로 남던 통제 불가 상태였다.)
- **가시성은 무효(검토 결과)**: `-fvisibility=hidden`+`_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS`+`OPENSSL_EXPORT=default` 식 심볼 숨김은 **COFF(UEFI 주 타깃)에서 효과 없음**(실측: 적용 전후 심볼 테이블 동일, std 심볼은 weak/COMDAT 그대로). COFF 엔 ELF 식 가시성 개념이 없기 때문. 충돌 회피는 ABI 네임스페이스가 전담하고, 가시성은 ELF 노출표면 정리용 보강일 뿐이라 채택하지 않았다.
- **병합**: `CMakeLists.txt` 의 crypto `POST_BUILD` 가 `util/korecrypto-merge-libcxx.cmake` 를 `cmake -P` 로 호출 → `${CMAKE_AR} -M`(MRI `addlib`)로 `liblibcxx.a`+`liblibcxxabi.a` 의 모든 멤버를 `libcrypto.a` 로 합친다. 임시 파일에 만든 뒤 원자적 교체. **멱등성**: CMake 가 crypto 재링크마다 libcrypto.a 를 crypto-only 로 새로 만들고 직후 이 단계가 도므로 중복이 없고, 추가로 센티넬 멤버(`private_typeinfo.cpp.o`)가 이미 있으면 건너뛴다.
- **링크**: build.rs 의 `static=libcxx`/`static=libcxxabi` 는 그대로 둔다. 정적 아카이브는 미해결 심볼이 있을 때만 멤버를 끌어오므로, 이미 libcrypto.a 가 제공한 libc++ 심볼 때문에 liblibcxx.a 멤버는 적재되지 않아 무해(중복 오류 없음). `static=crypto` 한 줄로 libc++ 까지 링크된다.
- **검증**(aarch64-unknown-uefi, COFF): 병합 후 `libcrypto.a` 309 멤버(crypto 273 + libcxx 23 + libcxxabi 13), `private_typeinfo.cpp.o` 포함, STL 심볼 네임스페이스 `std::__korecrypto`, `__cxa_pure_virtual`/`__cxa_throw` 등 libc++abi 런타임이 libcrypto.a 안에 정의됨. 스텁/`FORCE:MULTIPLE` 없이 smoketest `.efi` 링크 성공 — **libc++ 미해결/중복 심볼 0건**.

> 참고: libc++abi 의 ABI 표준 심볼(`operator new/delete`, `__cxa_*`)은 네임스페이스 격리 대상이 아니므로 이름이 유지된다. 정적 아카이브 링크에서는 모체가 동일 심볼을 정의해도 링커가 한쪽만 채택해 충돌하지 않는다("충돌 회피로 충분" 요건 충족).
>
> COFF 부분링크+localize 식 심볼 숨김은 aarch64 COFF 에서 불가능했다(lld-link 의 relocatable `-r` 미지원, llvm-objcopy 의 COFF localize 미지원, aarch64 mingw 부재) — ABI 네임스페이스 방식이 포맷 비의존이라 이 제약을 우회한다.

### 7.6 aarch64 UEFI: CPU 특성 검출(OPENSSL_cpuid_setup) — sysreg 경로 활성화 ✅

aarch64 에서 asm 을 켜면(`!OPENSSL_NO_ASM`) `crypto/internal.h` 가 `NEED_CPUID` 를 정의해 `crypto.cc` 가 `OPENSSL_cpuid_setup()` 을 참조한다. 그런데 그 **정의**는 `cpu_aarch64_<platform>.cc` 가 각자 특정 OS 매크로(`OPENSSL_LINUX/WINDOWS/APPLE/FREEBSD/FUCHSIA`, sysreg 는 `ANDROID_BAREMETAL||OPENSSL_FREEBSD`) 아래에서만 제공한다. UEFI(freestanding)는 어느 플랫폼에도 안 걸려 정의가 없어 `undefined symbol: bssl::OPENSSL_cpuid_setup()` 링크 오류가 났다(과거엔 no-op 스텁으로 우회).

- **수정**: `crypto/cpu_aarch64_sysreg.cc` 의 가드에 `KORECRYPTO_BAREMETAL` 을 추가. freestanding 에는 getauxval 등 OS 질의 수단이 없고 통합자가 EL1/EL2 에서 구동하므로 `MRS` 로 `id_aa64pfr0_el1`/`id_aa64isar0_el1` 을 직접 읽어 NEON/AES/SHA/PMULL 등을 실제 검출한다(다른 cpu_aarch64_*.cc 는 UEFI 에서 비게 되므로 중복 정의 없음). 스모크테스트의 `OPENSSL_cpuid_setup` 스텁 불필요.
- **검증**(aarch64-unknown-uefi, QEMU virt + cortex-a72): 스텁 없이 `.efi` 링크 성공, `libcrypto.a` 가 `OPENSSL_cpuid_setup`(T, sysreg.cc) 정의. 런타임 `FIPS_mode=1`, `BORINGSSL_integrity_test=1`, `BORINGSSL_self_test_all=1` → **RESULT: PASS** (MRS 트랩 없음, HW 검출 + libc++ 병합 상태에서도 FIPS 무결성·KAT 통과).

> 빌드 주의: `boring-sys/build.rs` 는 boringssl 소스에 대한 `rerun-if-changed` 를 선언하지 않으므로, **boringssl 소스만** 고친 뒤에는 cargo 가 build.rs 를 재실행하지 않아 cmake 가 재컴파일하지 않을 수 있다. 이 경우 `cargo clean -p korecrypto-sys`(또는 build.rs touch) 후 빌드한다. 클린 빌드는 정상 반영된다.
