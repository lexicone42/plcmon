//! Platform-specific setup for non-root packet capture.
//! - macOS: creates access_bpf group + LaunchDaemon (like Wireshark's ChmodBPF)
//! - Linux: grants CAP_NET_RAW capability on the plcmon binary

use std::process::Command;

pub fn run_setup() {
    #[cfg(target_os = "macos")]
    run_setup_macos();

    #[cfg(target_os = "linux")]
    run_setup_linux();

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("Setup not implemented for this platform.");
        eprintln!("You may need to run plcmon as root.");
    }
}

// ===========================================================================
// macOS
// ===========================================================================

#[cfg(target_os = "macos")]
fn run_setup_macos() {
    const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.plcmon.ChmodBPF.plist";
    const GROUP: &str = "access_bpf";

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.plcmon.ChmodBPF</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>chgrp access_bpf /dev/bpf* &amp;&amp; chmod g+rw /dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#;

    println!("plcmon setup (macOS)");
    println!("====================");
    println!("Creates '{GROUP}' group, adds your user, installs LaunchDaemon.");
    println!("Requires sudo.\n");

    let user = real_user();

    // 1. Create group
    print!("Creating group '{GROUP}'... ");
    let exists = Command::new("dseditgroup")
        .args(["-o", "read", GROUP])
        .output()
        .is_ok_and(|o| o.status.success());
    if exists {
        println!("already exists");
    } else {
        run_sudo(&["dseditgroup", "-o", "create", GROUP]);
        println!("done");
    }

    // Ensure GID is set (chgrp needs it)
    let has_gid = Command::new("dscl")
        .args([".", "-read", &format!("/Groups/{GROUP}"), "PrimaryGroupID"])
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty());
    if !has_gid {
        print!("Assigning GID... ");
        run_sudo(&[
            "dscl",
            ".",
            "-create",
            &format!("/Groups/{GROUP}"),
            "PrimaryGroupID",
            "710",
        ]);
        println!("done");
    }

    // 2. Add user
    print!("Adding '{user}' to '{GROUP}'... ");
    run_sudo(&[
        "dseditgroup",
        "-o",
        "edit",
        "-a",
        &user,
        "-t",
        "user",
        GROUP,
    ]);
    println!("done");

    // 3. Set BPF permissions now
    print!("Setting BPF permissions... ");
    run_sudo(&[
        "sh",
        "-c",
        &format!("chgrp {GROUP} /dev/bpf* && chmod g+rw /dev/bpf*"),
    ]);
    println!("done");

    // 4. Install LaunchDaemon
    print!("Installing LaunchDaemon... ");
    let tmp = "/tmp/dev.plcmon.ChmodBPF.plist";
    std::fs::write(tmp, PLIST).expect("write temp plist");
    run_sudo(&["cp", tmp, PLIST_PATH]);
    run_sudo(&["chown", "root:wheel", PLIST_PATH]);
    run_sudo(&["chmod", "644", PLIST_PATH]);
    println!("done");

    // 5. Load daemon
    print!("Loading daemon... ");
    let _ = Command::new("sudo")
        .args(["launchctl", "unload", PLIST_PATH])
        .output();
    run_sudo(&["launchctl", "load", PLIST_PATH]);
    println!("done");

    println!("\nSetup complete. You may need to log out/in for group membership.");
}

// ===========================================================================
// Linux
// ===========================================================================

#[cfg(target_os = "linux")]
fn run_setup_linux() {
    println!("plcmon setup (Linux)");
    println!("====================");
    println!("Grants CAP_NET_RAW on the plcmon binary so it can capture without root.");
    println!("Requires sudo.\n");

    // Find our own binary path
    let exe = std::env::current_exe().expect("cannot determine binary path");
    let exe_str = exe.to_string_lossy();

    print!("Setting cap_net_raw on {exe_str}... ");
    run_sudo(&["setcap", "cap_net_raw+ep", &exe_str]);
    println!("done");

    // Verify
    let check = Command::new("getcap").arg(&*exe_str).output();
    if let Ok(out) = check {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("cap_net_raw") {
            println!("\nSetup complete. plcmon can now capture without root.");
        } else {
            println!("\nWarning: capability may not have been set. You may need to run as root.");
        }
    }
}

// ===========================================================================
// Shared
// ===========================================================================

/// Get the real user even when running under sudo.
fn real_user() -> String {
    std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}

fn run_sudo(args: &[&str]) {
    let status = Command::new("sudo")
        .args(args)
        .status()
        .expect("failed to run sudo");
    if !status.success() {
        eprintln!("  warning: command failed: sudo {}", args.join(" "));
    }
}
