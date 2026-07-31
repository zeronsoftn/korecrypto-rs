use fslock::LockFile;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::process::{Command, Output};
use std::sync::OnceLock;

use crate::config::Config;

mod config;

fn should_use_cmake_cross_compilation(config: &Config) -> bool {
    if config.host == config.target {
        return false;
    }
    match config.target_os.as_str() {
        "macos" | "ios" => {
            // Cross-compiling for Apple platforms on macOS is supported using the normal Xcode
            // tools, along with the settings from `cmake_params_apple`.
            !config.host.ends_with("-darwin")
        }
        _ => true,
    }
}

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

fn cmake_params_android(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (android_arch, params) in CMAKE_PARAMS_ANDROID_NDK {
        if *android_arch == config.target_arch {
            return params;
        }
    }
    &[]
}

const CMAKE_PARAMS_APPLE: &[(&str, &[(&str, &str)])] = &[
    // iOS
    (
        "aarch64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    // macOS
    (
        "aarch64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
    (
        "x86_64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
];

fn cmake_params_apple(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (next_target, params) in CMAKE_PARAMS_APPLE {
        if *next_target == config.target {
            return params;
        }
    }
    &[]
}

fn get_apple_sdk_name(config: &Config) -> &'static str {
    for (name, value) in cmake_params_apple(config) {
        if *name == "CMAKE_OSX_SYSROOT" {
            return value;
        }
    }

    panic!(
        "cannot find SDK for {} in CMAKE_PARAMS_APPLE",
        config.target
    );
}

/// Returns an absolute path to the BoringSSL source.
fn get_boringssl_source_path(config: &Config) -> &Path {
    static SOURCE_PATH: OnceLock<PathBuf> = OnceLock::new();

    SOURCE_PATH.get_or_init(|| {
        if let Some(src_path) = &config.env.source_path {
            if !src_path.exists() {
                println!(
                    "cargo:warning=boringssl source path doesn't exist: {}",
                    src_path.display()
                );
            }
            return src_path.into();
        }

        let submodule_dir = "boringssl";

        let src_path = config.out_dir.join(submodule_dir);

        let submodule_path = config.manifest_dir.join("deps").join(submodule_dir);

        if !submodule_path.join("CMakeLists.txt").exists() {
            println!("cargo:warning=fetching boringssl git submodule");

            run_command(
                Command::new("git")
                    .args(["submodule", "update", "--init", "--recursive"])
                    .arg(&submodule_path),
            )
            .expect("git submodule update");
        }

        let _ = fs::remove_dir_all(&src_path);
        fs_extra::dir::copy(submodule_path, &config.out_dir, &Default::default())
            .inspect_err(|_| {
                let _ = fs::remove_dir_all(&config.out_dir);
            })
            .expect("copying failed. Try running `cargo clean`");

        // NOTE: .git can be both file and dir, depening on whether it was copied from a submodule
        // or created by the patches code.
        let src_git_path = src_path.join(".git");
        let _ = fs::remove_file(&src_git_path);
        let _ = fs::remove_dir_all(&src_git_path);

        src_path
    })
}

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: <https://github.com/alexcrichton/cmake-rs/issues/18>
fn msvc_lib_subdir(config: &Config) -> Option<&'static str> {
    if config.target.ends_with("-msvc") {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var = config
            .env
            .debug
            .as_ref()
            .expect("DEBUG variable not defined in env");

        let deb_info = match debug_env_var.to_str() {
            Some("false") => false,
            Some("true") => true,
            _ => panic!("Unknown DEBUG={debug_env_var:?} env var."),
        };

        let opt_env_var = config
            .env
            .opt_level
            .as_ref()
            .expect("OPT_LEVEL variable not defined in env");

        let subdir = match opt_env_var.to_str() {
            Some("0") => "Debug",
            Some("1" | "2" | "3") => {
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                }
            }
            Some("s" | "z") => "MinSizeRel",
            _ => panic!("Unknown OPT_LEVEL={opt_env_var:?} env var."),
        };

        Some(subdir)
    } else {
        None
    }
}

/// FIPS 크로스(리눅스) 빌드에서 clang 이 사용할 GNU `ld` 경로를 결정한다.
///
/// FIPS 는 clang 을 강제하는데 clang 은 rust 트리플용 prefix ld 를 못 찾아 호스트 ld 로
/// 폴백한다. 여기서는 cargo/CI 에 설정된 "대상 링커"(= rust 최종 링크에 쓰는 크로스 gcc)
/// 에게 `-print-prog-name=ld` 로 그 gcc 가 쓰는 ld 의 절대경로를 물어본다. 이 ld 를
/// clang(`-fuse-ld=`)과 최종 rust 링크 양쪽에 쓰면 크로스 링크가 되고 무결성 해시도
/// 일치한다. 절대경로를 하드코딩하지 않고 툴체인에서 동적으로 얻는다.
fn resolve_target_ld(config: &Config) -> Option<String> {
    let target_us = config.target.replace('-', "_");
    let target_env = target_us.to_uppercase();

    // 대상 gcc 후보: 1) cargo 링커 설정(env 형태), 2) cc-rs 형태 CC_<target>,
    // 3) rust 트리플에서 유도한 GNU 트리플(aarch64-unknown-linux-gnu → aarch64-linux-gnu-gcc).
    let mut candidates: Vec<String> = [
        std::env::var(format!("CARGO_TARGET_{target_env}_LINKER")).ok(),
        std::env::var(format!("CC_{}", config.target)).ok(),
        std::env::var(format!("CC_{target_us}")).ok(),
    ]
    .into_iter()
    .flatten()
    .collect();
    candidates.push(format!("{}-gcc", config.target.replace("-unknown-", "-")));

    for cc in candidates {
        let Ok(output) = Command::new(&cc).arg("-print-prog-name=ld").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let ld = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // gcc 가 자신의 ld 를 해소하면 절대경로를 준다. 해소 못 하면 그냥 "ld" 라
        // 돌려주므로(호스트 ld) 경로 형태일 때만 채택한다.
        if ld.contains('/') {
            return Some(ld);
        }
    }
    None
}

/// Returns a new `cmake::Config` for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config(config: &Config) -> cmake::Config {
    let src_path = get_boringssl_source_path(config);
    let mut boringssl_cmake = cmake::Config::new(src_path);

    // Visual Studio Generator 에서는 CMAKE_C_COMPILER(clang) 이 무시된다.
    boringssl_cmake.generator("Ninja");

    boringssl_cmake.define("CMAKE_SUPPRESS_REGENERATION", "ON");

    if config.env.cmake_toolchain_file.is_some() {
        return boringssl_cmake;
    }

    if config.features.fips {
        // clang 을 사용하는데 cl 문법이 들어가는 오류 방지.
        boringssl_cmake.no_default_flags(true);
    }

    // CRT(런타임 라이브러리) 선택. windows-msvc 타깃(cl, 또는 MSVC ABI 를
    // 시뮬레이트하는 clang)에서만 적용한다. CMake 는 Debug config + 기본값
    // MultiThreadedDLL 로 항상 런타임 라이브러리 플래그(/MDd 상당: _DLL+_DEBUG,
    // --dependent-lib=msvcrtd)를 주입하므로, 이를 -fms-runtime-lib 같은 컴파일
    // 플래그로 덮어쓰려 하면 두 CRT 가 동시에 링크되어 깨진다. 반드시 CMake 의
    // CMAKE_MSVC_RUNTIME_LIBRARY 추상화로 제어해야 한다. +crt-static 인 rust 는
    // 정적 릴리스 CRT(libcmt)로 링크하므로 boringssl 도 MultiThreaded 로 맞춘다
    // (그렇지 않으면 __imp_*/_wassert/_CrtDbgReport 미해결 심볼 발생).
    //
    // windows-gnu(예: msys CLANG64, SIMULATE_ID=GNU)에는 적용하지 않는다. 그쪽
    // clang 은 MSVC 런타임 추상화를 지원하지 않아 CMAKE_MSVC_RUNTIME_LIBRARY 가
    // 빌드를 깨뜨린다. (FIPS 여부와 무관하게 msvc 환경이면 필요하다.)
    // https://github.com/rust-lang/cmake-rs/pull/30#issuecomment-2969758499
    if config.target_os == "windows" && config.target_env == "msvc" {
        if config.target_features.iter().any(|f| f == "crt-static") {
            boringssl_cmake.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreaded");
        } else {
            boringssl_cmake.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreadedDLL");
        }
    }

    if config.host == config.target {
        return boringssl_cmake;
    }

    if should_use_cmake_cross_compilation(config) {
        let clang_target = config.clang_target();
        boringssl_cmake
            .define("CMAKE_CROSSCOMPILING", "true")
            .define("CMAKE_C_COMPILER_TARGET", &clang_target)
            .define("CMAKE_CXX_COMPILER_TARGET", &clang_target)
            .define("CMAKE_ASM_COMPILER_TARGET", &clang_target);

        // FIPS 는 clang 을 강제한다(아래 build 단계). 리눅스 크로스에서 clang 은 rust
        // 트리플용 prefix ld(예: aarch64-unknown-linux-gnu-ld)를 못 찾아 호스트 ld 로
        // 폴백해 링크가 깨지고, 무결성 해시도 최종 rust 링크(GNU ld)와 어긋난다. 대상
        // 링커(= cargo/CI 에 설정된 크로스 gcc)에게 물어본 ld 경로를 clang 의 `-fuse-ld`
        // 로 넘겨(모든 링크 단계 = compiler test/공유객체/실행), 최종 rust 링크와 동일한
        // ld 를 쓰게 한다. cmake 툴체인 파일은 수정하지 않는다(하드코딩 X, 단일 지점).
        if config.features.fips && config.target_os == "linux" {
            if let Some(ld) = resolve_target_ld(config) {
                let fuse_ld = format!("-fuse-ld={ld}");
                boringssl_cmake
                    .define("CMAKE_EXE_LINKER_FLAGS", &fuse_ld)
                    .define("CMAKE_SHARED_LINKER_FLAGS", &fuse_ld)
                    .define("CMAKE_MODULE_LINKER_FLAGS", &fuse_ld);
            } else {
                let t_env = config.target.to_uppercase().replace('-', "_");
                println!(
                    "cargo:warning=FIPS cross build: 대상 링커의 `ld` 를 찾지 못했습니다. \
                     CARGO_TARGET_{t_env}_LINKER 또는 CC_{} 를 크로스 gcc 로 설정하세요.",
                    config.target
                );
            }
        }
    }

    if !config.features.fips {
        if let Some(cc) = &config.env.cc {
            boringssl_cmake.define("CMAKE_C_COMPILER", cc);
        }
        if let Some(cxx) = &config.env.cxx {
            boringssl_cmake.define("CMAKE_CXX_COMPILER", cxx);
        }
    }

    if let Some(sysroot) = &config.env.sysroot {
        boringssl_cmake.define("CMAKE_SYSROOT", sysroot);
    }

    if let Some(toolchain) = &config.env.compiler_external_toolchain {
        boringssl_cmake
            .define("CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_ASM_COMPILER_EXTERNAL_TOOLCHAIN", toolchain);
    }

    // Add platform-specific parameters for cross-compilation.
    match &*config.target_os {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = config
                .env
                .android_ndk_home
                .as_ref()
                .expect("Please set ANDROID_NDK_HOME for Android build");
            for (name, value) in cmake_params_android(config) {
                eprintln!("android arch={} add {}={}", config.target_arch, name, value);
                boringssl_cmake.define(name, value);
            }
            let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
            let toolchain_file = toolchain_file.to_str().unwrap();
            eprintln!("android toolchain={toolchain_file}");
            boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

            // 21 is the minimum level tested. You can give higher value.
            boringssl_cmake.define("CMAKE_SYSTEM_VERSION", "21");
            boringssl_cmake.define("CMAKE_ANDROID_STL_TYPE", "c++_shared");
        }

        "macos" => {
            for (name, value) in cmake_params_apple(config) {
                eprintln!("macos arch={} add {}={}", config.target_arch, name, value);
                boringssl_cmake.define(name, value);
            }
        }

        "ios" => {
            for (name, value) in cmake_params_apple(config) {
                eprintln!("ios arch={} add {}={}", config.target_arch, name, value);
                boringssl_cmake.define(name, value);
            }

            // Bitcode is always on.
            let bitcode_cflag = "-fembed-bitcode";

            // Hack for Xcode 10.1.
            let target_cflag = if config.target_arch == "x86_64" {
                "-target x86_64-apple-ios-simulator"
            } else {
                ""
            };

            let cflag = format!("{bitcode_cflag} {target_cflag}");
            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);
        }

        "linux" => match &*config.target_arch {
            "x86" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    // `src_path` can be a path relative to the manifest dir, but
                    // cmake hates that.
                    config
                        .manifest_dir
                        .join(src_path)
                        .join("util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }
            "aarch64" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/aarch64-linux.cmake")
                        .as_os_str(),
                );
            }
            "arm" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/armv7-linux.cmake")
                        .as_os_str(),
                );
            }
            _ => {
                println!(
                    "cargo:warning=no toolchain file configured by boring-sys for {}",
                    config.target
                );
            }
        },

        _ => {}
    }

    if config.features.uefi {
        boringssl_cmake.define("KORECRYPTO_UEFI", "1");
    }

    // UEFI/baremetal(freestanding) + picolibc 빌드 구성.
    // picolibc 크레이트가 `links = "c"` 로 내보내는 include 디렉터리를
    // `DEP_C_INCLUDE` 로 받아 BoringSSL CMake 빌드에 `BAREMETAL_LIBC_INCLUDE` 로 전달한다.
    if config.features.picolibc {
        let libc_include = std::env::var("DEP_C_INCLUDE").expect(
            "picolibc feature 가 켜져 있으면 DEP_C_INCLUDE 가 설정되어야 합니다 \
             (picolibc 의존성이 links=\"c\" 로 노출). cargo clean 후 다시 빌드해 보세요.",
        );
        // bare-metal(freestanding) 공통 구성. picolibc feature 자체가 freestanding
        // 신호이므로 OS 와 무관하게 적용한다(외부 libc include + 번들 libc++).
        boringssl_cmake
            // 외부 freestanding libc(picolibc) 의 include 디렉터리.
            .define("BAREMETAL_LIBC_INCLUDE", &libc_include)
            // freestanding 에는 시스템 C++ 표준 라이브러리가 없으므로 번들
            // libc++/libc++abi 를 함께 빌드한다.
            .define("USE_CUSTOM_LIBCXX", "1")
            // try_compile 도 실행 파일이 아닌 정적 라이브러리로(링크 단계 회피).
            .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY");
    }

    boringssl_cmake
}

fn pick_best_android_ndk_toolchain(toolchains_dir: &Path) -> io::Result<OsString> {
    let toolchains = std::fs::read_dir(toolchains_dir)?.collect::<Result<Vec<_>, _>>()?;
    // First look for one of the toolchains that Google has documented.
    // https://developer.android.com/ndk/guides/other_build_systems
    for known_toolchain in ["linux-x86_64", "darwin-x86_64", "windows-x86_64"] {
        if let Some(toolchain) = toolchains
            .iter()
            .find(|entry| entry.file_name() == known_toolchain)
        {
            return Ok(toolchain.file_name());
        }
    }
    // Then fall back to any subdirectory, in case Google has added support for a new host.
    // (Maybe there's a linux-aarch64 toolchain now.)
    if let Some(toolchain) = toolchains
        .into_iter()
        .find(|entry| entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false))
    {
        return Ok(toolchain.file_name());
    }
    // Finally give up.
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no subdirectories at given path",
    ))
}

fn get_extra_clang_args_for_bindgen(config: &Config) -> Vec<String> {
    let mut params = Vec::new();

    // Add platform-specific parameters.
    match &*config.target_os {
        "ios" | "macos" => {
            // When cross-compiling for Apple targets, tell bindgen to use SDK sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = get_apple_sdk_name(config);
            match run_command(Command::new("xcrun").args(["--show-sdk-path", "--sdk", sdk])) {
                Ok(output) => {
                    let sysroot = std::str::from_utf8(&output.stdout).expect("xcrun output");
                    params.push("-isysroot".to_string());
                    // There is typically a newline at the end which confuses clang.
                    params.push(sysroot.trim_end().to_string());
                }
                Err(e) => {
                    println!("cargo:warning={e}");
                    // Uh... let's try anyway, I guess?
                }
            }
        }
        "android" => {
            let mut android_sysroot = config
                .env
                .android_ndk_home
                .clone()
                .expect("Please set ANDROID_NDK_HOME for Android build");

            android_sysroot.extend(["toolchains", "llvm", "prebuilt"]);

            match pick_best_android_ndk_toolchain(&android_sysroot) {
                Ok(toolchain) => {
                    android_sysroot.push(toolchain);
                    android_sysroot.push("sysroot");
                    params.push("--sysroot".to_string());
                    params.push(android_sysroot.into_os_string().into_string().unwrap());
                }
                Err(e) => {
                    println!("cargo:warning=failed to find prebuilt Android NDK toolchain for bindgen: {e}");
                    // Uh... let's try anyway, I guess?
                }
            }
        }
        _ => {
            if config.features.baremetal {
                // BoringSSL 공개 헤더는 base.h 를 통해 stdlib.h/sys/types.h 를 포함하는데,
                // UEFI 에서는 이를 picolibc 가 공급한다. libclang 이 picolibc 헤더를
                // 찾고, uefi 타깃으로 헤더를 파싱하도록 인자를 추가한다.
                if let Ok(inc) = std::env::var("DEP_C_INCLUDE") {
                    params.push("-I".to_string());
                    params.push(inc);
                }
                params.push(format!("--target={}", config.clang_target()));
            } else if config.target_os == "windows" && config.target_env == "msvc" {
                // libclang 은 자신이 빌드된 기본 타깃으로 헤더를 파싱한다. msys2
                // CLANG64 셸처럼 PATH 상의 libclang 이 *-windows-gnu 기본 타깃을
                // 가지면 MSVC UCRT 가 아니라 C:/msys64/clang64/include 의 GNU
                // stdlib.h 를 물고, BoringSSL 공개 헤더 파싱이 `expected ';'`
                // 류의 에러로 실패한다. MSVC ABI 타깃을 명시한다.
                params.push(format!("--target={}", config.clang_target()));
            }
        }
    }

    params
}

fn ensure_patches_applied(config: &Config) -> io::Result<()> {
    if config.env.assume_patched || config.env.path.is_some() {
        println!(
            "cargo:warning=skipping git patches application, provided\
            native BoringSSL is expected to have the patches included"
        );
        return Ok(());
    } else if config.env.source_path.is_some()
        && (config.features.rpk || config.features.underscore_wildcards)
    {
        panic!(
            "BORING_BSSL_ASSUME_PATCHED must be set when setting
               BORING_BSSL_SOURCE_PATH and using any of the following
               features: rpk, underscore-wildcards"
        );
    }

    let lock_file_path = config.out_dir.join(".patch_lock");
    if lock_file_path.exists() {
        return Ok(());
    }
    let mut lock_file = LockFile::open(&lock_file_path)?;
    let src_path = get_boringssl_source_path(config);
    let has_git = src_path.join(".git").exists();

    lock_file.lock()?;

    // NOTE: init git in the copied files, so we can apply patches
    if !has_git {
        run_command(Command::new("git").arg("init").current_dir(src_path))?;
    }

    if config.features.allow_crl_extensions_bad_version {
        println!(
            "cargo:warning=applying the patch for disabling cert version \
            validation for extensions"
        );
        apply_patch(config, "bad-cert-verification.patch")?;
    }

    println!("cargo:warning=applying post quantum crypto patch to boringssl");
    apply_patch(config, "boring-pq.patch")?;

    if config.features.rpk {
        println!("cargo:warning=applying RPK patch to boringssl");
        apply_patch(config, "rpk.patch")?;
    }

    if config.features.underscore_wildcards {
        println!("cargo:warning=applying underscore wildcards patch to boringssl");
        apply_patch(config, "underscore-wildcards.patch")?;
    }

    Ok(())
}

fn apply_patch(config: &Config, patch_name: &str) -> io::Result<()> {
    let src_path = get_boringssl_source_path(config);
    #[cfg(not(windows))]
    let cmd_path = config
        .manifest_dir
        .join("patches")
        .join(patch_name)
        .canonicalize()?;

    #[cfg(windows)]
    let cmd_path = config.manifest_dir.join("patches").join(patch_name);

    let mut args = vec!["apply", "-v", "--whitespace=fix"];

    // non-bazel versions of BoringSSL have no src/ dir
    if config.is_bazel {
        args.push("-p2");
    }

    run_command(
        Command::new("git")
            .args(&args)
            .arg(cmd_path)
            .current_dir(src_path),
    )?;

    Ok(())
}

fn run_command(command: &mut Command) -> io::Result<Output> {
    let out = command.output().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "can't run {}: {e}\n{command:?} failed",
                command.get_program().to_string_lossy(),
            ),
        )
    })?;

    std::io::stderr().write_all(&out.stderr)?;
    std::io::stdout().write_all(&out.stdout)?;

    if !out.status.success() {
        let err = match out.status.code() {
            Some(code) => format!("{command:?} exited with status: {code}"),
            None => format!("{command:?} was terminated by signal"),
        };

        return Err(io::Error::other(err));
    }

    Ok(out)
}

fn build_boringssl_or_get_prebuilt(config: &Config) -> &Path {
    static BUILD_SOURCE_PATH: OnceLock<PathBuf> = OnceLock::new();

    BUILD_SOURCE_PATH.get_or_init(|| {
        if let Some(path) = &config.env.path {
            if !path.exists() {
                println!("cargo:warning=built path doesn't exist: {}", path.display());
            }
            return path.into();
        }

        let mut cfg = get_boringssl_cmake_config(config);

        let num_jobs = std::env::var("NUM_JOBS").ok().or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(|t| t.to_string())
        });
        if let Some(num_jobs) = num_jobs {
            cfg.env("CMAKE_BUILD_PARALLEL_LEVEL", num_jobs);
        }

        // FIPS(delocate)와 picolibc(freestanding + USE_CUSTOM_LIBCXX)은 clang 을
        // 강제한다. cc-rs 가 기본 주입하는 플래그(예: uefi→windows-gnu 로의 `--target`)도
        // 비워 CMAKE_*_COMPILER_TARGET 으로만 타깃을 지정하게 한다. 이 초기화가 없으면
        // 비-FIPS UEFI 빌드에서 CMake 가 컴파일러를 GNU 로 인식해 USE_CUSTOM_LIBCXX 검사가
        // 실패한다. (컴파일러는 PATH 상의 clang — UEFI 는 clang>=19 필요하므로 호출부가
        // PATH/CC 로 clang-22 등을 지정한다.)
        if config.features.fips || config.features.picolibc {
            cfg.define("CMAKE_C_COMPILER", "clang")
                .define("CMAKE_CXX_COMPILER", "clang++")
                .define("CMAKE_ASM_COMPILER", "clang")
                .define("CMAKE_C_FLAGS", "")
                .define("CMAKE_CXX_FLAGS", "")
                .define("CMAKE_ASM_FLAGS", "");
        }
        if config.features.fips {
            cfg.define("FIPS", "1");
        }

        // bare-metal(freestanding, picolibc) 빌드는 crypto 만 빌드한다. ssl 은 소켓/
        // 시계 등 OS 의존 헤더(sys/socket.h 등)를 요구해 freestanding 에서 빌드되지
        // 않으며, bare-metal 용도(KCMVP 암호 모듈)에는 TLS 스택이 필요 없다.
        let crypto_only = config.features.baremetal || config.features.picolibc;
        if !crypto_only {
            cfg.build_target("ssl").build();
        }
        let path = cfg.build_target("crypto").build();
        let build_dir = path.join("build");
        if build_dir.exists() {
            build_dir
        } else {
            path
        }
    })
}

fn get_cpp_runtime_lib(config: &Config) -> Option<String> {
    if let Some(ref cpp_lib) = config.env.cpp_runtime_lib {
        return cpp_lib.clone().into_string().ok();
    }

    match &*config.target_os {
        "macos" | "ios" | "freebsd" | "openbsd" | "android" => Some("c++".into()),
        _ if config.unix || config.target_env == "gnu" => Some("stdc++".into()),
        // TODO(rmehra): figure out how to do this for windows
        _ => None,
    }
}

/// Copies built BoringSSL artifacts (libraries and patched headers) into a
/// user-specified directory. This is intended for producing a pre-built package.
///
/// The destination directory must exist and be empty. Writes:
///
///   - `lib/libcrypto.a`
///   - `lib/libssl.a`
///   - `lib/bcm.o` (if FIPS is enabled)
///   - `include/openssl/...` (patched headers)
fn install_artifacts(
    config: &Config,
    install_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let install_dir = match install_dir.canonicalize() {
        Ok(dir) if dir.read_dir().is_ok_and(|mut d| d.next().is_none()) => dir,
        dir => {
            let path = dir.as_deref().unwrap_or(install_dir).display();
            return Err(format!("{path} must be an empty dir").into());
        }
    };
    let bssl_build_dir = build_boringssl_or_get_prebuilt(config);

    let lib_dir = install_dir.join("lib");
    fs::create_dir(&lib_dir)?;

    for lib in ["libcrypto.a", "libssl.a", "bcm.o"] {
        if !config.features.fips && lib == "bcm.o" {
            continue;
        }
        fs::copy(bssl_build_dir.join(lib), lib_dir.join(lib))?;
    }

    fs_extra::dir::copy(get_include_path(config)?, &install_dir, &Default::default())?;

    eprintln!(
        "installed BoringSSL artifacts into {}",
        install_dir.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("boring-sys failed: {e}");
        println!(
            "cargo::error={}",
            e.to_string().trim_ascii().replace('\n', "\ncargo::error=")
        );
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `dir` 하위의 C/C++ 소스·헤더 파일을 재귀적으로 찾아 rerun-if-changed 로 등록한다.
/// 감시 대상은 빌드 입력(.h/.hpp/.c/.cc/.cpp/.inc)만. 존재하지 않는 경로는 조용히
/// 무시한다(예: source_path 구성 차이).
fn emit_rerun_if_changed_recursive(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            emit_rerun_if_changed_recursive(&path);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "h" | "hpp" | "c" | "cc" | "cpp" | "inc") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;

    // rerun-if-changed 는 반드시 빌드의 "입력" 파일을 가리켜야 한다.
    // get_boringssl_source_path() 는 source_path 미설정 시 deps/boringssl 을 OUT_DIR 로
    // 복사한 경로를 돌려주는데, 그 복사본은 매 빌드마다 build.rs 가 새로 만들어 mtime 이
    // 갱신된다. 복사본을 감시하면 cargo 가 항상 "변경됨"으로 판단해
    // build.rs 재실행 → 재복사 → ninja 전체 재빌드가 무한 반복된다. 따라서 복사 이전의
    // 원본 소스(source_path 또는 submodule deps/boringssl)를 감시한다.
    let watch_src = config
        .env
        .source_path
        .clone()
        .unwrap_or_else(|| config.manifest_dir.join("deps").join("boringssl"));
    println!(
        "cargo:rerun-if-changed={}",
        watch_src.join("CMakeLists.txt").display()
    );
    // CMakeLists.txt 뿐 아니라 실제 빌드 입력인 C/C++ 소스와 공개 헤더도 감시한다.
    // 이렇게 하지 않으면 crypto/*.cc(.inc) 나 include/openssl/*.h 를 고쳐도 build.rs 가
    // 재실행되지 않아 OUT_DIR 복사본·libcrypto.a·bindgen 산출물이 stale 로 남는다
    // (예: crypto.h 에 함수를 추가해도 ffi 바인딩이 생성되지 않음). watch_src 는 복사
    // 이전의 원본이라 build.rs 가 수정하지 않으므로 감시해도 무한 재빌드가 없다.
    for sub in ["include", "crypto"] {
        emit_rerun_if_changed_recursive(&watch_src.join(sub));
    }
    ensure_patches_applied(&config)?;
    if !config.env.docs_rs {
        emit_link_directives(&config);
    }
    generate_bindings(&config).map_err(|e| format!("could not generate bindings: {e}"))?;
    if let Some(install_dir) = &config.env.export_to_install_dir {
        install_artifacts(&config, install_dir)
            .map_err(|e| format!("install artifacts failed: {e}"))?;
    }
    Ok(())
}

fn emit_link_directives(config: &Config) {
    let bssl_dir = build_boringssl_or_get_prebuilt(config);
    let msvc_lib_subdir = msvc_lib_subdir(config);

    let subdirs =
        if config.is_bazel || (config.features.is_kcmvp_like() && config.env.path.is_some()) {
            &["lib"][..]
        } else {
            &["lib", "crypto", "ssl", ""][..]
        };

    for subdir in subdirs {
        let dir = bssl_dir.join(subdir);
        let dir = msvc_lib_subdir
            .map(|s| dir.join(s))
            .filter(|d| d.exists())
            .unwrap_or(dir);
        println!("cargo:rustc-link-search=native={}", dir.display());
    }

    if let Some(cpp_lib) = get_cpp_runtime_lib(config) {
        println!("cargo:rustc-link-lib={cpp_lib}");
    }
    println!("cargo:rustc-link-lib=static=crypto");
    // bare-metal(freestanding, picolibc) 에서는 ssl 을 빌드하지 않으므로 링크도 하지
    // 않는다. (생성된 SSL FFI 선언은 호출되지 않는 한 링크를 요구하지 않는다.)
    if !config.features.picolibc {
        println!("cargo:rustc-link-lib=static=ssl");
    }

    if config.target_os == "windows" {
        // Rust 1.87.0 compat - https://github.com/rust-lang/rust/pull/138233
        println!("cargo:rustc-link-lib=advapi32");
    }

    // FIPS windows-msvc 빌드는 _NO_CRT_STDIO_INLINE 로 stdio 인라인을 끈다(모듈 .text 에
    // CRT 글루가 박혀 무결성 해시가 깨지는 것을 막기 위함 — build_boringssl 참고). 그러면
    // UCRT 의 레거시 named 심볼(_vsnprintf 등)이 인라인으로 제공되지 않아, 이를 공급하는
    // legacy_stdio_definitions 를 최종 링크에 추가해야 한다(모듈 밖 함수라 해시엔 무관).
    if config.features.fips && config.target_os == "windows" && config.target_env == "msvc" {
        println!("cargo:rustc-link-lib=legacy_stdio_definitions");
    }
}

fn check_include_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.join("openssl").join("x509v3.h").exists() {
        Ok(path)
    } else {
        Err(format!(
            "Include path {} {}",
            path.display(),
            if !path.exists() {
                "does not exist"
            } else {
                "does not have expected openssl/x509v3.h"
            }
        ))
    }
}

fn get_include_path(config: &Config) -> Result<PathBuf, String> {
    if let Some(path) = &config.env.include_path {
        return check_include_path(path.to_owned());
    }

    if let Some(bssl_path) = &config.env.path {
        return check_include_path(bssl_path.join("include"));
    }

    let src_path = get_boringssl_source_path(config);
    check_include_path(src_path.join("include"))
        .or_else(|_| check_include_path(src_path.join("src").join("include")))
}

fn generate_bindings(config: &Config) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let include_path = get_include_path(config)?;

    let target_rust_version = bindgen::RustTarget::stable(77, 0)
        .map_err(|e| format!("bindgen does not recognize target rust version: {e}"))?;

    let mut builder = bindgen::Builder::default()
        .rust_target(target_rust_version) // bindgen MSRV is 1.70, so this is enough
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(false)
        .derive_partialeq(false)
        // no_std 호환: 생성 바인딩이 std 대신 core 를 참조하게 한다(UEFI 등
        // freestanding 타깃 지원). std 타깃에서도 core::ffi 타입은 동일하다.
        .use_core()
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        // UEFI 에서는 레이아웃 테스트를 끈다. clang 은 x86_64-unknown-uefi 를 LLP64
        // (long=4)로 보지만 Rust 의 core::ffi::c_long 은 (target_os=uefi 가 windows 가
        // 아니라) i64 로 정의되어, `long` 을 쓰는 구조체(ldiv_t/fd_set 등)의 크기
        // 단언이 어긋난다. crypto API 는 이런 타입을 쓰지 않으므로 단언만 비활성화한다.
        .layout_tests(config.env.debug.is_some() && config.target_os != "uefi")
        .merge_extern_blocks(true)
        .prepend_enum_name(true)
        .blocklist_type("max_align_t") // Not supported by bindgen on all targets, not used by BoringSSL
        .clang_args(get_extra_clang_args_for_bindgen(config))
        .clang_arg("-I")
        .clang_arg(include_path.display().to_string());

    if config.features.uefi {
        builder = builder.clang_arg("-DKORECRYPTO_UEFI")
    }
    if config.features.baremetal {
        builder = builder.clang_arg("-DKORECRYPTO_BAREMETAL")
    }

    if let Some(sysroot) = &config.env.sysroot {
        builder = builder
            .clang_arg("--sysroot")
            .clang_arg(sysroot.display().to_string());

        // we need to add special platform header file with env for support cross building
        let target_include_dir = sysroot.join(format!(
            "usr/include/{}-{}-{}",
            config.target_arch, config.target_os, config.target_env
        ));
        if target_include_dir.is_dir() {
            builder = builder
                .clang_arg("-I")
                .clang_arg(target_include_dir.display().to_string());
        }
    }

    let must_have_headers = [
        "aes.h",
        "aria.h",
        "lea.h",
        "seed.h",
        "hight.h",
        "lsh.h",
        "kbkdf.h",
        "drbg_kcmvp.h",
        "ctrdrbg.h",
        "eckcdsa.h",
        "kcdsa.h",
        "asn1_mac.h",
        "asn1t.h",
        "blake2.h",
        "blowfish.h",
        "cast.h",
        "chacha.h",
        "cmac.h",
        "cpu.h",
        "curve25519.h",
        "des.h",
        "dtls1.h",
        "err.h",
        "hkdf.h",
        "hpke.h",
        "ossl_typ.h",
        "pkcs12.h",
        "poly1305.h",
        "x509v3.h",
    ];
    let headers = [
        "hmac.h",
        "hrss.h",
        "md4.h",
        "md5.h",
        "mldsa.h",
        "mlkem.h",
        "obj_mac.h",
        "objects.h",
        "opensslv.h",
        "rand.h",
        "rc4.h",
        "ripemd.h",
        "siphash.h",
        "slhdsa.h",
        "srtp.h",
        "tls_prf.h",
        "trust_token.h",
    ];
    for (i, header) in must_have_headers.into_iter().chain(headers).enumerate() {
        let header_path = include_path.join("openssl").join(header);
        if header_path.exists() {
            builder = builder.header(header_path.to_str().unwrap());
        } else {
            let err = format!("'openssl/{header}' is missing from '{}'. The include path may be incorrect or contain an outdated version of OpenSSL/BoringSSL", include_path.display());
            if i < must_have_headers.len() {
                return Err(err.into());
            }
            println!("cargo::warning={err}");
        }
    }

    let bindings = builder.generate()?;
    let mut source_code = Vec::new();
    bindings
        .write(Box::new(&mut source_code))
        .map_err(|e| format!("Couldn't serialize bindings: {e}"))?;
    ensure_err_lib_enum_is_named(&mut source_code);
    let bindings_path = config.out_dir.join("bindings.rs");
    fs::write(&bindings_path, source_code).map_err(|e| {
        format!(
            "Couldn't write bindings to {}: {e}",
            bindings_path.display()
        )
    })?;
    Ok(bindings_path)
}

/// err.h has anonymous `enum { ERR_LIB_NONE = 1 }`, which makes a dodgy `_bindgen_ty_1` name
fn ensure_err_lib_enum_is_named(source_code: &mut Vec<u8>) {
    let src = String::from_utf8_lossy(source_code);
    let enum_type = src
        .split_once("ERR_LIB_SSL:")
        .and_then(|(_, def)| Some(def.split_once('=')?.0))
        .unwrap_or("_bindgen_ty_1");

    source_code.extend_from_slice(
        format!("\n/// Newtype for [`ERR_LIB_SSL`] constants\npub use {enum_type} as ErrLib;\n")
            .as_bytes(),
    );
}
