use std::{collections::HashMap, net::TcpStream};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub started_at: String,
    pub executable: String,
    pub command: String,
}

pub fn inspect_process_tree(pid: u32, limit: usize) -> Result<Vec<ProcessIdentity>, String> {
    if pid == 0 {
        return Err("Invalid process ID".into());
    }
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut current = pid;
    while current > 0 && result.len() < limit && visited.insert(current) {
        let Some(identity) = inspect_process(current)? else {
            break;
        };
        let parent = identity.ppid;
        result.push(identity);
        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }
    Ok(result)
}

pub fn same_process(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid
        && left.started_at == right.started_at
        && left.executable == right.executable
}

pub fn is_launchd_process(process: &ProcessIdentity) -> bool {
    let executable = process
        .executable
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let invoked = process
        .command
        .trim()
        .replace('\\', "/")
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    executable == "launchd" || invoked == "launchd"
}

/// The live identities of these processes, keyed by PID. Processes that have exited are left out.
#[cfg(not(target_os = "macos"))]
pub fn inspect_processes(pids: &[u32]) -> Result<HashMap<u32, ProcessIdentity>, String> {
    pids.iter()
        .filter_map(|&pid| inspect_process(pid).transpose())
        .map(|identity| identity.map(|identity| (identity.pid, identity)))
        .collect()
}

/// Whether the process still runs. A failed inspection says nothing about the process, so it
/// counts as running rather than ending a grant early.
pub fn process_is_alive(process: &ProcessIdentity) -> bool {
    match inspect_process(process.pid) {
        Ok(current) => current.is_some_and(|current| same_process(&current, process)),
        Err(_) => true,
    }
}

/// Whether the process still runs under the parent it had. Its parent exiting orphans it, for
/// example when a timeout kills the shell that ran it. A failed inspection says nothing about the
/// process, so it counts as unchanged rather than ending a wait early.
pub fn process_runs_under_parent(process: &ProcessIdentity) -> bool {
    match inspect_process(process.pid) {
        Ok(current) => current
            .is_some_and(|current| same_process(&current, process) && current.ppid == process.ppid),
        Err(_) => true,
    }
}

pub fn omit_secretd_client_processes(tree: &[ProcessIdentity]) -> Vec<ProcessIdentity> {
    tree.iter()
        .skip_while(|process| is_secretd_client_process(process))
        .cloned()
        .collect()
}

pub fn is_secretd_client_process(process: &ProcessIdentity) -> bool {
    let command = process
        .command
        .trim()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let executable = process
        .executable
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let invoked = command
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if executable == "secretd" || invoked == "secretd" {
        return true;
    }
    executable == "deno"
        && (command.contains("deno task cli") || command.contains("src/cli/main.ts"))
}

pub fn verify_connection_owner(pid: u32, connection: &TcpStream) -> bool {
    let Ok(local) = connection.local_addr() else {
        return false;
    };
    let Ok(peer) = connection.peer_addr() else {
        return false;
    };
    verify_connection_tuple(pid, peer.port(), local.port())
}

#[cfg(target_os = "macos")]
fn inspect_process(pid: u32) -> Result<Option<ProcessIdentity>, String> {
    Ok(inspect_processes(&[pid])?.remove(&pid))
}

/// The live identities of these processes, keyed by PID. Processes that have exited are left out.
/// Two `ps` calls cover any number of processes.
#[cfg(target_os = "macos")]
pub fn inspect_processes(pids: &[u32]) -> Result<HashMap<u32, ProcessIdentity>, String> {
    if pids.is_empty() {
        return Ok(HashMap::new());
    }
    let commands: HashMap<u32, String> = ps(pids, "pid=,command=")?
        .lines()
        .filter_map(|line| {
            let (pid, command) = split_words(line, 1)?;
            Some((pid.parse().ok()?, command.trim_end().to_string()))
        })
        .collect();
    let identities = ps(pids, "pid=,ppid=,lstart=,comm=")?
        .lines()
        .filter_map(|line| {
            let (pid, ppid, started_at, executable) = parse_ps_identity(line)?;
            // A process that started between the two calls under one of these PIDs has no
            // command, so it is left out.
            let command = commands.get(&pid)?.clone();
            let identity = ProcessIdentity {
                pid,
                ppid,
                started_at,
                executable,
                command,
            };
            Some((pid, identity))
        })
        .collect();
    Ok(identities)
}

#[cfg(target_os = "macos")]
fn ps(pids: &[u32], fields: &str) -> Result<String, String> {
    let pids = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    // The output is read as UTF-8, and the C time format keeps the start time at five words in
    // any language. An inherited LC_ALL would override both, so it is removed. UTC keeps a
    // timezone change from changing the start time used to identify a running process.
    let output = Command::new("/bin/ps")
        .args(["-p", &pids, "-o", fields])
        .env_remove("LC_ALL")
        .env("LC_CTYPE", "UTF-8")
        .env("LC_TIME", "C")
        .env("TZ", "UTC0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    // ps fails when none of the processes exist, and prints nothing for them.
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parses a `ps -o pid=,ppid=,lstart=,comm=` line. The start time is five words, and the program
/// path after it can contain spaces.
#[cfg(any(target_os = "macos", test))]
fn parse_ps_identity(line: &str) -> Option<(u32, u32, String, String)> {
    let (pid, rest) = split_words(line, 1)?;
    let (ppid, rest) = split_words(rest, 1)?;
    let (started_at, executable) = split_words(rest, 5)?;
    let executable = executable.trim_end();
    Some((
        pid.parse().ok()?,
        ppid.parse().ok()?,
        started_at.to_string(),
        executable.to_string(),
    ))
}

/// Splits the first `count` words off a line, keeping the spacing between them, from the rest.
#[cfg(any(target_os = "macos", test))]
fn split_words(line: &str, count: usize) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let mut rest = line;
    for _ in 0..count {
        let word = rest.split_whitespace().next()?;
        rest = rest.trim_start().strip_prefix(word)?;
    }
    Some((&line[..line.len() - rest.len()], rest.trim_start()))
}

#[cfg(target_os = "macos")]
fn verify_connection_tuple(pid: u32, client_port: u16, server_port: u16) -> bool {
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:ESTABLISHED",
            "-Fn",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let expected = format!("127.0.0.1:{client_port}->127.0.0.1:{server_port}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.starts_with('n') && line.contains(&expected))
}

#[cfg(target_os = "linux")]
fn inspect_process(pid: u32) -> Result<Option<ProcessIdentity>, String> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.to_string()),
    };
    let Some(closing) = stat.rfind(')') else {
        return Ok(None);
    };
    let fields: Vec<_> = stat[closing + 1..].split_whitespace().collect();
    let (Some(ppid), Some(started_at)) = (fields.get(1), fields.get(19)) else {
        return Ok(None);
    };
    let Ok(ppid) = ppid.parse::<u32>() else {
        return Ok(None);
    };
    let executable = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => return Ok(None),
    };
    let command = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|_| executable.clone());
    Ok(Some(ProcessIdentity {
        pid,
        ppid,
        started_at: (*started_at).into(),
        executable,
        command,
    }))
}

#[cfg(target_os = "linux")]
fn verify_connection_tuple(pid: u32, client_port: u16, server_port: u16) -> bool {
    let Ok(table) = fs::read_to_string("/proc/net/tcp") else {
        return false;
    };
    let expected_local = format!("0100007F:{client_port:04X}");
    let expected_remote = format!("0100007F:{server_port:04X}");
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.len() >= 10
            && fields[1] == expected_local
            && fields[2] == expected_remote
            && fields[3] == "01")
            .then(|| fields[9].to_string())
    });
    let Some(inode) = inode else {
        return false;
    };
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        fs::read_link(entry.path())
            .is_ok_and(|target| target.to_string_lossy() == format!("socket:[{inode}]"))
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn inspect_process(_pid: u32) -> Result<Option<ProcessIdentity>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn verify_connection_tuple(_pid: u32, _client_port: u16, _server_port: u16) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, executable: &str, command: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid: pid.saturating_sub(1),
            started_at: pid.to_string(),
            executable: executable.into(),
            command: command.into(),
        }
    }

    #[test]
    fn removes_compiled_and_development_clients() {
        let cli = process(30, "/usr/local/bin/secretd", "secretd get service/token");
        let deno = process(20, "/opt/bin/deno", "deno task cli get service/token");
        let shell = process(10, "/bin/zsh", "zsh");
        assert_eq!(
            omit_secretd_client_processes(&[cli, deno, shell.clone()]),
            [shell]
        );
    }

    #[test]
    fn checks_the_full_identity_of_a_live_process() {
        let current = inspect_process_tree(std::process::id(), 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert!(process_is_alive(&current));
        assert!(process_runs_under_parent(&current));

        // It was recorded under a parent it no longer runs under, as if that parent had exited.
        let mut orphaned = current.clone();
        orphaned.ppid = u32::MAX;
        assert!(process_is_alive(&orphaned));
        assert!(!process_runs_under_parent(&orphaned));

        let mut reused_pid = current;
        reused_pid.started_at.push_str("-different");
        assert!(!process_is_alive(&reused_pid));
        assert!(!process_runs_under_parent(&reused_pid));
    }

    #[test]
    fn inspects_several_processes_at_once() {
        let current = std::process::id();
        let expected = inspect_process_tree(current, 1).unwrap().remove(0);
        let live = inspect_processes(&[current, 1]).unwrap();
        assert_eq!(live.get(&current), Some(&expected));
        assert!(inspect_processes(&[]).unwrap().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn process_start_times_use_utc() {
        let pid = std::process::id();
        let expected = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .env("LC_ALL", "C")
            .env("TZ", "UTC0")
            .output()
            .unwrap();
        assert!(expected.status.success());
        let actual = inspect_process(pid).unwrap().unwrap();
        assert_eq!(
            actual.started_at,
            String::from_utf8(expected.stdout).unwrap().trim()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_process_can_have_a_blank_program_name() {
        use std::os::unix::process::CommandExt;

        let mut child = Command::new("/bin/sleep")
            .arg0("   ")
            .arg("60")
            .spawn()
            .unwrap();
        let identity = inspect_process(child.id());
        let _ = child.kill();
        let _ = child.wait();

        let identity = identity.unwrap().expect("the process is still running");
        assert_eq!(identity.pid, child.id());
        assert!(identity.executable.is_empty());
    }

    #[test]
    fn parses_ps_lines_with_padded_dates_and_spaced_paths() {
        let (pid, ppid, started_at, executable) = parse_ps_identity(
            "  312   301 Fri Oct  9 08:05:12 2026     /Applications/T3 Code.app/Contents/MacOS/T3 Code",
        )
        .unwrap();
        assert_eq!((pid, ppid), (312, 301));
        assert_eq!(started_at, "Fri Oct  9 08:05:12 2026");
        assert_eq!(
            executable,
            "/Applications/T3 Code.app/Contents/MacOS/T3 Code"
        );
        assert!(parse_ps_identity("312 301 Fri Oct 9 08:05:12").is_none());
        assert!(parse_ps_identity("pid 301 Fri Oct 9 08:05:12 2026 /bin/zsh").is_none());
        assert_eq!(
            parse_ps_identity("312 301 Fri Oct 9 08:05:12 2026     "),
            Some((312, 301, "Fri Oct 9 08:05:12 2026".into(), String::new()))
        );
        assert_eq!(
            split_words("  42 aws sts get-caller-identity ", 1),
            Some(("42", "aws sts get-caller-identity "))
        );
    }

    #[test]
    fn identifies_launchd_by_pid_or_executable() {
        assert!(is_launchd_process(&process(
            1,
            "/sbin/launchd",
            "/sbin/launchd"
        )));
        assert!(is_launchd_process(&process(
            99,
            "/sbin/launchd",
            "/sbin/launchd"
        )));
        assert!(!is_launchd_process(&process(20, "/bin/zsh", "-zsh")));
        assert!(!is_launchd_process(&process(1, "/sbin/init", "/sbin/init")));
    }
}
