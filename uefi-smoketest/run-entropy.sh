#!/usr/bin/env bash
# uefi-smoketest 를 `entropy-dump` 기능으로 빌드해 QEMU + OVMF 로 부팅하고, 게스트가
# 시리얼로 덤프하는 KCMVP 잡음원 샘플(hex)을 캡처해 엔트로피 평가 파일(*.txt)로
# 만든다. 샘플 수집은 게스트 안에서 실제 KCMVP 모듈 경로
# (KCMVP_entropy_raw_noise_samples → bssl::entropy::GetSamples)로 수행된다.
#
# 사용법:
#   ./run-entropy.sh [출력파일]
# 출력파일 기본값: entropy-uefi-<arch>.txt
#
# 주요 환경변수(run-qemu.sh 와 동일): TARGET_TRIPLE, QEMU, OVMF_CODE, LIBCLANG_PATH 등
set -euo pipefail

INVOKE_DIR="$PWD"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -d /usr/lib/llvm-22/bin ]; then
  export PATH="/usr/lib/llvm-22/bin:$PATH"
fi
export PICOLIBC_CC="${PICOLIBC_CC:-clang-22}"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-22/lib}"

TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-uefi}"
TARGET_ARCH=$(echo "${TARGET_TRIPLE}" | cut -d'-' -f1)
OUTFILE="${1:-entropy-uefi-${TARGET_ARCH}.txt}"
# 상대 경로 출력은 스크립트 실행 위치(INVOKE_DIR) 기준으로 고정한다(아래에서
# SCRIPT_DIR 로 cd 하므로).
case "$OUTFILE" in
  /*) ;;
  *) OUTFILE="$INVOKE_DIR/$OUTFILE" ;;
esac

echo "TARGET_ARCH=${TARGET_ARCH}"

DEFAULT_QEMU=""
if [ "${TARGET_ARCH}" == "x86_64" ]; then
  DEFAULT_QEMU=qemu-system-x86_64
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU_MACHINE_DEFAULT="-machine q35 -accel kvm -cpu qemu64"
  else
    QEMU_MACHINE_DEFAULT="-machine q35 -accel tcg -cpu qemu64"
  fi
  QEMU_MACHINE="${QEMU_MACHINE:-$QEMU_MACHINE_DEFAULT}"
  OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
elif [ "${TARGET_ARCH}" == "aarch64" ]; then
  export PICOLIBC_CLANG_TARGET=aarch64-unknown-windows-gnu
  export KORECRYPTO_CLANG_TARGET=$PICOLIBC_CLANG_TARGET
  DEFAULT_QEMU=qemu-system-aarch64
  QEMU_MACHINE=${QEMU_MACHINE:-"-machine virt -accel tcg,thread=multi -cpu cortex-a72"}
  OVMF_CODE="${OVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.fd}"
fi
QEMU="${QEMU:-${DEFAULT_QEMU}}"

TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"
EFI="$TARGET_DIR/${TARGET_TRIPLE}/debug/uefi-smoketest.efi"

echo "[*] building uefi-smoketest (entropy-dump) ..."
cargo build -p uefi-smoketest --target "${TARGET_TRIPLE}" --features entropy-dump ${CARGO_FLAGS:-}
test -f "$EFI" || { echo "[ERR] .efi not found: $EFI"; exit 1; }

# 호스트용 포맷터(entropy-assess)를 준비한다. format 서브커맨드는 모듈을 호출하지
# 않으므로 kcmvp 없이 빌드한다.
echo "[*] building entropy-assess (host formatter) ..."
cargo build --manifest-path "$SCRIPT_DIR/../Cargo.toml" -p entropy-assess
FORMATTER="$SCRIPT_DIR/../target/debug/entropy-assess"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SERIAL_LOG="$WORK/serial.log"

echo "[*] running QEMU (collecting 250000 samples via serial) ..."
set +e
timeout --foreground 900 "$QEMU" \
  $QEMU_MACHINE -m 512 \
  -display none \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
  -device virtio-rng-pci \
  -kernel "$EFI" \
  -serial stdio \
  -no-reboot \
  2>"$WORK/qemu.err" | tee "$SERIAL_LOG" >/dev/null
QEMU_RC=${PIPESTATUS[0]}
set -e

if ! grep -q "ENTROPY_END ok=1" "$SERIAL_LOG"; then
  echo "[FAIL] 잡음원 수집 실패 (ENTROPY_END ok=1 없음, qemu rc=$QEMU_RC)"
  echo "--- serial tail ---"; tail -20 "$SERIAL_LOG" || true
  echo "--- qemu stderr ---"; tail -20 "$WORK/qemu.err" 2>/dev/null || true
  exit 1
fi

# bits 값 추출(기본 8).
BITS=$(grep -oE 'ENTROPY_BEGIN num=[0-9]+ bits=[0-9]+' "$SERIAL_LOG" | head -1 | grep -oE 'bits=[0-9]+' | cut -d= -f2)
BITS="${BITS:-8}"

# 시리얼에서 'EDATA <hex>' 토큰을 순서대로 추출 → 원시 바이트로 복원.
grep -oE 'EDATA [0-9A-F]+' "$SERIAL_LOG" | sed 's/EDATA //' | tr -d '\n' | xxd -r -p > "$WORK/raw.bin"
NBYTES=$(wc -c < "$WORK/raw.bin")
echo "[*] captured $NBYTES samples (bits=$BITS)"

"$FORMATTER" format --bits "$BITS" --input "$WORK/raw.bin" "$OUTFILE"
echo "[OK] wrote $OUTFILE"
