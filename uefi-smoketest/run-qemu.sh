#!/usr/bin/env bash
# uefi-smoketest 를 x86_64-unknown-uefi 로 빌드해 실제 .efi 를 만들고, QEMU + OVMF 로
# 부팅한 뒤 시리얼(`-serial stdio`) 출력에서 FIPS 자가시험 결과를 검증한다.
#
# 통과 조건: 시리얼에 "RESULT: PASS" 가 나타나면 성공(exit 0), 아니면 실패(exit 1).
#
# 사용법:
#   ./run-qemu.sh
# 주요 환경변수(미설정 시 합리적 기본값):
#   CC_x86_64_unknown_uefi / CXX_x86_64_unknown_uefi  (기본 clang-22 / clang++-22)
#   PICOLIBC_CC            (기본 clang-22)
#   LIBCLANG_PATH         (기본 /usr/lib/llvm-22/lib)
#   OVMF_CODE / OVMF_VARS (기본 /usr/share/OVMF/OVMF_CODE_4M.fd, OVMF_VARS_4M.fd)
#   QEMU                  (기본 qemu-system-x86_64)
#   개발 트리에서 build.rs 의 소스 복사가 느리거나 실패하면 아래를 미리 export:
#     BORING_BSSL_FIPS_SOURCE_PATH=<...>/boring-sys/deps/boringssl
#     BORING_BSSL_FIPS_ASSUME_PATCHED=1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

## --- boring-sys 소스 복사 우회 ---
## boring-sys build.rs 는 기본적으로 deps/boringssl 전체를 OUT_DIR 로 복사한다.
## 개발 트리에 수동 빌드 산출물(build-*/SAMPLE/util/bot/llvm-project-src 등)이 있으면
## 복사가 실패한다. 로컬 서브모듈이 있으면 복사 없이 제자리 빌드하도록 SOURCE_PATH 를
## 자동으로 설정한다.
#BSSL_SRC="$SCRIPT_DIR/../boring-sys/deps/boringssl/CMakeLists.txt"
#if [ -z "${BORING_BSSL_FIPS_SOURCE_PATH:-}" ] && [ -f "$BSSL_SRC" ]; then
#  export BORING_BSSL_FIPS_SOURCE_PATH
#  BORING_BSSL_FIPS_SOURCE_PATH="$(cd "$SCRIPT_DIR/../boring-sys/deps/boringssl" && pwd)"
#  export BORING_BSSL_FIPS_ASSUME_PATCHED=1
#  echo "[*] 로컬 boringssl 서브모듈 사용 (복사 우회): $BORING_BSSL_FIPS_SOURCE_PATH"
#fi

# --- 툴체인 기본값(clang >= 19 필요) ---
if [ -d /usr/lib/llvm-22/bin ]; then
  export PATH="/usr/lib/llvm-22/bin:$PATH"
fi
# 셸 식별자에는 '-' 를 못 쓰므로 cargo/cc-rs 가 동일하게 인식하는 밑줄 형식을 쓴다.
#export CC_x86_64_unknown_uefi="${CC_x86_64_unknown_uefi:-clang-22}"
#export CXX_x86_64_unknown_uefi="${CXX_x86_64_unknown_uefi:-clang++-22}"
export PICOLIBC_CC="${PICOLIBC_CC:-clang-22}"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-22/lib}"

TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-uefi}"
TARGET_ARCH=$(echo "${TARGET_TRIPLE}" | cut -d'-' -f1)

echo "TARGET_ARCH=${TARGET_ARCH}"

DEFAULT_QEMU=""
if [ "${TARGET_ARCH}" == "x86_64" ]; then
  DEFAULT_QEMU=qemu-system-x86_64
  QEMU_MACHINE="-machine q35 -accel kvm -cpu host"
  OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
elif [ "${TARGET_ARCH}" == "aarch64" ]; then
  export PICOLIBC_CLANG_TARGET=aarch64-unknown-windows-gnu
  export KORECRYPTO_CLANG_TARGET=$PICOLIBC_CLANG_TARGET
  DEFAULT_QEMU=qemu-system-aarch64
  QEMU_MACHINE="-machine virt -accel tcg,thread=multi -cpu cortex-a72 -device virtio-gpu-pci"
  OVMF_CODE="${OVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}"
fi

QEMU="${QEMU:-${DEFAULT_QEMU}}"

TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"
EFI="$TARGET_DIR/${TARGET_TRIPLE}/debug/uefi-smoketest.efi"

echo "[*] building uefi-smoketest (.efi) ..."
cargo build -p uefi-smoketest --target ${TARGET_TRIPLE}
test -f "$EFI" || { echo "[ERR] .efi not found: $EFI"; exit 1; }
echo "[*] built: $EFI"

WORK="$(mktemp -d)"
echo "WORK=$WORK"

trap 'rm -rf "$WORK"' EXIT
SERIAL_LOG="$WORK/serial.log"

echo "[*] running QEMU (OVMF, -kernel) ..."

# OVMF 는 `-kernel` 로 전달된 PE 를 EFI 애플리케이션으로 로드·실행한다.
# 게스트 COM1 → `-serial stdio` 로 호스트 stdout 에 캡처한다.
set +e
# SLH-DSA(SPHINCS+) 자가시험은 순수 C SHA 로 수십만~수백만 해시를 돌려 매우 느리므로
# 넉넉한 타임아웃을 준다. PIPESTATUS[0] 로 (tee 가 아니라) QEMU 의 종료코드를 받는다.
timeout --foreground 600 "$QEMU" \
  $QEMU_MACHINE -m 256 \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
  -device virtio-rng-pci \
  -kernel "$EFI" \
  -serial stdio \
  -no-reboot \
  2>"$WORK/qemu.err" | tee "$SERIAL_LOG"
QEMU_RC=${PIPESTATUS[0]}
set -e

echo "----------------------------------------"
if grep -q "RESULT: PASS" "$SERIAL_LOG"; then
  echo "[OK] FIPS 자가시험 통과 (serial: RESULT: PASS)"
  exit 0
else
  echo "[FAIL] 'RESULT: PASS' 를 시리얼 출력에서 찾지 못함 (qemu rc=$QEMU_RC)"
  echo "--- qemu stderr ---"; cat "$WORK/qemu.err" 2>/dev/null | tail -20 || true
  exit 1
fi
