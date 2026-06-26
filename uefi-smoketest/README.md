# uefi-smoketest

`korecrypto-sys` 의 **picolibc + UEFI** 연동을 `x86_64-unknown-uefi` 타깃으로 실제
**링크까지** 검증하는 최소 UEFI 애플리케이션이다. 런타임 동작이 아니라 "링크가
끊기는 심볼이 없는지"를 확인하는 빌드 스모크 테스트다(실제 동작 검증은 QEMU/OVMF
같은 실제 UEFI 환경 필요).

상위 워크스페이스(host 타깃 빌드)와 섞이지 않도록 **독립 워크스페이스**로 둔다.

## 요구사항

- **clang >= 19** (clang 18 이하의 `x86_64-unknown-uefi` 데이터 레이아웃 버그 때문에
  미지원). 이 저장소 개발 환경에는 `clang-22`(`/usr/lib/llvm-22`)가 있다.
- `rustup target add x86_64-unknown-uefi`
- libclang(>=19) — bindgen 용. `LIBCLANG_PATH` 로 지정.
- FIPS 빌드용 `go`, 그리고 delocate 가 쓰는 llvm 도구(`PATH` 에 llvm-19+ bin).

## 빌드

```sh
export PATH="/usr/lib/llvm-22/bin:$PATH"
export CC_x86_64-unknown-uefi=clang-22
export CXX_x86_64-unknown-uefi=clang++-22
export PICOLIBC_CC=clang-22                 # picolibc(cc-rs)도 clang>=19 강제
export LIBCLANG_PATH=/usr/lib/llvm-22/lib    # bindgen

cargo build --target x86_64-unknown-uefi
```

산출물: `target/x86_64-unknown-uefi/debug/uefi-smoketest.efi` (PE32+ EFI application).

### 개발 트리에서 빌드가 오래 걸리거나 복사가 실패할 때

`korecrypto-sys` build.rs 는 기본적으로 `deps/boringssl` 를 `OUT_DIR` 로 복사한다.
수동 빌드 산출물(`build-*/`, `SAMPLE/`, `util/bot/llvm-project-src/` ~2.7G)로 트리가
커져 있거나 깨진 심볼릭 링크가 있으면 복사가 느리거나 실패할 수 있다. 그럴 때는
복사 없이 제자리에서 빌드하도록 source-path 를 지정한다(FIPS 변수):

```sh
export BORING_BSSL_FIPS_SOURCE_PATH=/absolute/path/to/boring-sys/deps/boringssl
export BORING_BSSL_FIPS_ASSUME_PATCHED=1     # CMake 는 OUT_DIR 에 out-of-source 빌드
```

> 깨끗한 체크아웃(수동 산출물 없음)에서는 위 source-path 없이도 빌드된다.
> `USE_CUSTOM_LIBCXX` 가 필요로 하는 llvm-project 는 CMake 가 필요 시 자동으로
> 받는다(`util/bot/llvm-project-src`).

## 무엇을 검증하나

- BoringSSL **crypto**(FIPS) 가 `x86_64-unknown-uefi` 로 picolibc 헤더에 대해 컴파일.
- picolibc(libc/libm) + `malloc`(Rust 전역 할당자=uefi global_allocator) 링크.
- 번들 libc++/libc++abi 링크, no_std `korecrypto-sys` 링크.
- MS x64 ABI 스택 프로빙(`__chkstk`) 및 picolibc freestanding 스텁 충족.

ssl(TLS) 은 소켓 등 OS 의존성으로 UEFI 에서 빌드하지 않는다(crypto 전용).
