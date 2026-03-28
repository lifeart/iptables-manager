use tauri::State;

use crate::ipc::errors::IpcError;

use super::helpers::PoolProxyExecutor;
use super::types::SafetyTimerResult;
use super::AppState;

/// Schedule a safety revert timer on the remote host.
#[tauri::command]
pub async fn set_safety_timer(
    host_id: String,
    timeout_secs: u32,
    state: State<'_, AppState>,
) -> Result<SafetyTimerResult, IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Detect the best available mechanism
    let mechanism = crate::safety::timer::detect_mechanism(&proxy).await;

    // Schedule the revert
    let backup_path = "/var/lib/traffic-rules/snapshots/pre-apply.rules";
    let job = crate::safety::timer::schedule_revert(&proxy, mechanism, backup_path, timeout_secs)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("safety timer: {}", e),
            exit_code: 1,
        })?;

    Ok(SafetyTimerResult {
        job_id: job.id,
        mechanism: format!("{:?}", job.mechanism),
    })
}

/// Cancel a previously scheduled safety revert timer.
#[tauri::command]
pub async fn clear_safety_timer(
    host_id: String,
    job_id: String,
    mechanism: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    let proxy = PoolProxyExecutor {
        pool: state.pool.clone(),
        host_id: host_id.clone(),
    };

    // Determine the mechanism from the string, defaulting to At
    let mech = match mechanism.as_deref() {
        Some("At") => crate::safety::timer::SafetyMechanism::At,
        Some("SystemdRun") => crate::safety::timer::SafetyMechanism::SystemdRun,
        Some("Nohup") => crate::safety::timer::SafetyMechanism::Nohup,
        Some("IptablesApply") => crate::safety::timer::SafetyMechanism::IptablesApply,
        _ => crate::safety::timer::SafetyMechanism::At,
    };

    let revert_job = crate::safety::timer::RevertJobId {
        mechanism: mech,
        id: job_id,
    };

    crate::safety::timer::cancel_revert(&proxy, &revert_job)
        .await
        .map_err(|e| IpcError::CommandFailed {
            stderr: format!("cancel safety timer: {}", e),
            exit_code: 1,
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::helpers::tests::MockExecutor;

    #[tokio::test]
    async fn test_schedule_and_cancel_at_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("at", 0, "", "job 42 at Thu Mar 22 10:00:00 2026\n"),
            ("atrm", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::At,
            "/var/lib/traffic-rules/backup.v4",
            60,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(job.id, "42");
        assert_eq!(job.mechanism, crate::safety::timer::SafetyMechanism::At);

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");

        let calls = executor.get_calls();
        assert!(
            calls.iter().any(|c| c.contains("atrm")),
            "should call atrm to cancel"
        );
    }

    #[tokio::test]
    async fn test_schedule_and_cancel_systemd_run_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("systemd-run", 0, "", ""),
            ("systemctl", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::SystemdRun,
            "/var/lib/traffic-rules/backup.v4",
            120,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(
            job.mechanism,
            crate::safety::timer::SafetyMechanism::SystemdRun
        );
        assert!(
            job.id.starts_with("traffic-rules-revert-"),
            "systemd unit name should have expected prefix"
        );

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");
    }

    #[tokio::test]
    async fn test_schedule_and_cancel_nohup_roundtrip() {
        let executor = MockExecutor::new(vec![
            ("tee", 0, "", ""),
            ("chmod", 0, "", ""),
            ("nohup", 0, "12345\n", ""),
            ("kill", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::Nohup,
            "/var/lib/traffic-rules/backup.v4",
            30,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(job.mechanism, crate::safety::timer::SafetyMechanism::Nohup);
        assert_eq!(job.id, "12345");

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");
    }

    #[tokio::test]
    async fn test_at_schedule_uses_minutes() {
        let executor = MockExecutor::new(vec![
            ("at", 0, "", "job 99 at Thu Mar 22 10:05:00 2026\n"),
        ]);

        let _job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::At,
            "/var/lib/traffic-rules/backup.v4",
            90,
        )
        .await
        .expect("schedule should succeed");

        let calls = executor.get_calls();
        let at_call = calls
            .iter()
            .find(|c| c.starts_with("at "))
            .expect("should have called at");

        assert!(
            at_call.contains("minutes"),
            "at command should use minutes, got: {}",
            at_call
        );
        assert!(
            !at_call.contains("seconds"),
            "at command should NOT use seconds, got: {}",
            at_call
        );
        assert!(
            at_call.contains("2 minutes"),
            "90 seconds should round up to 2 minutes, got: {}",
            at_call
        );
    }

    #[tokio::test]
    async fn test_at_cancel_verifies_with_atq() {
        let executor = MockExecutor::new(vec![
            ("at", 0, "", "job 55 at Thu Mar 22 10:00:00 2026\n"),
            ("atrm", 0, "", ""),
            ("atq", 0, "", ""),
        ]);

        let job = crate::safety::timer::schedule_revert(
            &executor,
            crate::safety::timer::SafetyMechanism::At,
            "/var/lib/traffic-rules/backup.v4",
            60,
        )
        .await
        .expect("schedule should succeed");

        assert_eq!(job.id, "55");

        let cancel_result = crate::safety::timer::cancel_revert(&executor, &job).await;
        assert!(cancel_result.is_ok(), "cancel should succeed");

        let calls = executor.get_calls();

        let atrm_idx = calls
            .iter()
            .position(|c| c.contains("atrm"))
            .expect("should call atrm");
        let atq_idx = calls
            .iter()
            .position(|c| c.contains("atq"))
            .expect("should call atq to verify cancellation");
        assert!(
            atrm_idx < atq_idx,
            "atrm (idx {}) must come before atq verification (idx {})",
            atrm_idx,
            atq_idx
        );
    }
}
