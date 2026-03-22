# SSH Connection Layer

## Library: `openssh` crate

```rust
use openssh::{Session, KnownHosts, SessionBuilder};

async fn connect(config: &ConnectionConfig) -> Result<Session, ConnectError> {
    let mut builder = SessionBuilder::default();
    builder.known_hosts_check(KnownHosts::Strict);
    builder.port(config.port);
    builder.user(config.username.clone());

    if let Some(key) = &config.key_path {
        builder.keyfile(key);
    }
    if let Some(jump) = &config.jump_host {
        builder.jump_host(format!("{}@{}:{}", jump.username, jump.hostname, jump.port));
    }

    builder.connect(&config.hostname).await.map_err(ConnectError::from)
}
```

`openssh` inherits `~/.ssh/config`, `known_hosts`, SSH agent, ProxyJump — all transparently.

## Connection Pool

```rust
struct ConnectionPool {
    sessions: RwLock<HashMap<String, Arc<ManagedSession>>>,
    apply_locks: DashMap<String, Arc<Mutex<()>>>,  // per-host, prevents concurrent applies
}

struct ManagedSession {
    session: openssh::Session,
    config: ConnectionConfig,
    concurrency: Arc<Semaphore>,        // tokio Semaphore, permits=3
    cancel: CancellationToken,          // for background tasks
    last_used: AtomicInstant,
    health: AtomicU8,                   // 0=Healthy, 1=Degraded, 2=Dead
    reconnect_attempts: AtomicU32,
}
```

- `RwLock<HashMap>` for the pool (read-heavy, small map)
- `Semaphore` limits concurrent commands per host (not channel reuse — SSH channels are NOT reusable after exec)
- `CancellationToken` stops background tasks (monitoring, reconnect) on disconnect
- `DashMap` for per-host apply locks — prevents concurrent applies corrupting rulesets

## Command Execution

**SSH `exec` is always a shell string.** The Rust backend constructs safe command strings:

```rust
use shell_words;

fn build_command(program: &str, args: &[&str]) -> String {
    let mut all = vec![program.to_string()];
    all.extend(args.iter().map(|a| a.to_string()));
    shell_words::join(&all)
}

// Usage:
let cmd = build_command("sudo", &[
    "iptables", "-w", "5",
    "-I", "INPUT", "1",
    "-p", "tcp", "--dport", &port.to_string(),
    "-j", "ACCEPT"
]);
session.command("bash").arg("-c").arg(&cmd).output().await?;
```

For `iptables-restore`: data piped via stdin (never passes through shell):

```rust
async fn restore(session: &Session, data: &str, noflush: bool) -> Result<()> {
    let mut cmd = session.command("sudo");
    cmd.arg("iptables-restore").arg("-w").arg("5");
    if noflush { cmd.arg("--noflush"); }
    cmd.stdin(data.as_bytes());
    let output = cmd.output().await?;
    if !output.status.success() {
        return Err(ApplyError::RestoreFailed(stderr_to_string(&output.stderr)));
    }
    Ok(())
}
```

### Comment Sanitization

```rust
fn sanitize_comment(input: &str) -> Result<String, ValidationError> {
    if input.len() > 256 { return Err(CommentTooLong); }
    if input.contains('\n') || input.contains('\r') || input.contains('\0') {
        return Err(InvalidChars);
    }
    Ok(input.to_string())  // shell escaping handled by build_command()
}
```

## Credential Management

```
Flow:
  1. User enters password/passphrase in UI
  2. Frontend calls invoke('cred:store', { hostId, credential })
  3. Rust stores in OS keychain via `keyring` crate
  4. On connect: Rust retrieves from keychain, passes to openssh
  5. Credentials NEVER cross IPC back to frontend

Keychain unavailability:
  - macOS Keychain locked → prompt user to unlock
  - Linux without libsecret → fall back to encrypted file in app data dir
  - Show clear setup instructions for Linux keyring
```

## Reconnection

```
On disconnect:
  1. Emit 'connection:lost' event
  2. Cancel background tasks (monitoring) via CancellationToken
  3. Immediate reconnect (0ms)
  4. Backoff: 1s, 2s, 4s, 8s, 16s, 30s (cap)
  5. After 5 failures: mark 'unreachable', stop
  6. Frontend shows "Retry Connection"

On reconnect:
  1. Re-fetch iptables-save
  2. Compare hash with lastSyncedRuleHash
  3. If different: mark 'drifted', emit drift with diff
  4. Check for pending safety timer jobs (backup file exists?)
  5. Restart monitoring tasks
```

## Health Monitoring

Every 30s (5s during safety timer):
1. Run `echo ok` via SSH — if no response in 10s → degraded
2. 3 consecutive failures → disconnected → trigger reconnect
3. Emit `connection:status` on every change

## Host Provisioning (first connect)

After detection, before any rule management:

```rust
async fn provision_host(session: &Session) -> Result<ProvisionResult> {
    // 1. Create app directory
    exec(session, "sudo mkdir -p /var/lib/traffic-rules/snapshots").await?;
    exec(session, "sudo chmod 0700 /var/lib/traffic-rules").await?;

    // 2. Install revert script
    let revert_script = include_str!("../scripts/revert.sh");
    write_file(session, "/var/lib/traffic-rules/revert.sh", revert_script, "0755").await?;

    // 3. Generate and store HMAC secret
    let secret = generate_random_hex(32);
    write_file(session, "/var/lib/traffic-rules/.hmac_secret", &secret, "0600").await?;
    // Also store in local keychain for verification
    keychain_store(&format!("hmac-{}", host_id), &secret)?;

    // 4. Verify sudo access for required commands
    verify_sudo(session, &["iptables-save", "iptables-restore", "ipset"]).await?;

    Ok(ProvisionResult { success: true })
}
```

## Public API

```rust
pub async fn connect(host_id: &str, config: &ConnectionConfig) -> Result<()>;
pub async fn disconnect(host_id: &str) -> Result<()>;
pub async fn execute(host_id: &str, program: &str, args: &[&str]) -> Result<CommandOutput>;
pub async fn pipe_stdin(host_id: &str, program: &str, args: &[&str], stdin: &[u8]) -> Result<CommandOutput>;
pub async fn open_stream(host_id: &str, command: &str) -> Result<StreamHandle>;
pub fn get_status(host_id: &str) -> ConnectionStatus;
pub fn get_management_ip(host_id: &str) -> Option<String>;
pub async fn provision(host_id: &str) -> Result<ProvisionResult>;
```
