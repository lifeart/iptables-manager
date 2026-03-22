use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyStrategy {
    Canary,
    Rolling,
    Parallel,
}

/// The step-level plan for a single host or batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyStep {
    /// Which hosts to apply to in this step.
    pub host_ids: Vec<String>,
    /// Whether this step is the canary step.
    pub is_canary: bool,
    /// Maximum number of concurrent applies in this step.
    pub max_concurrency: usize,
}

/// Structured plan that the IPC layer would execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiApplyPlan {
    pub strategy: ApplyStrategy,
    pub host_ids: Vec<String>,
    pub canary_host: Option<String>,
    /// Ordered steps to execute.
    pub steps: Vec<ApplyStep>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_PARALLEL_CONCURRENCY: usize = 5;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn create_apply_plan(strategy: ApplyStrategy, host_ids: Vec<String>) -> MultiApplyPlan {
    if host_ids.is_empty() {
        return MultiApplyPlan {
            strategy,
            host_ids,
            canary_host: None,
            steps: vec![],
        };
    }

    match strategy {
        ApplyStrategy::Canary => {
            let canary = host_ids[0].clone();
            let remaining: Vec<String> = host_ids[1..].to_vec();

            let mut steps = vec![ApplyStep {
                host_ids: vec![canary.clone()],
                is_canary: true,
                max_concurrency: 1,
            }];

            if !remaining.is_empty() {
                steps.push(ApplyStep {
                    host_ids: remaining,
                    is_canary: false,
                    max_concurrency: MAX_PARALLEL_CONCURRENCY,
                });
            }

            MultiApplyPlan {
                strategy: ApplyStrategy::Canary,
                host_ids,
                canary_host: Some(canary),
                steps,
            }
        }
        ApplyStrategy::Rolling => {
            let steps = host_ids
                .iter()
                .map(|h| ApplyStep {
                    host_ids: vec![h.clone()],
                    is_canary: false,
                    max_concurrency: 1,
                })
                .collect();

            MultiApplyPlan {
                strategy: ApplyStrategy::Rolling,
                host_ids,
                canary_host: None,
                steps,
            }
        }
        ApplyStrategy::Parallel => {
            // All hosts in one step, capped at MAX_PARALLEL_CONCURRENCY.
            let steps = vec![ApplyStep {
                host_ids: host_ids.clone(),
                is_canary: false,
                max_concurrency: MAX_PARALLEL_CONCURRENCY,
            }];

            MultiApplyPlan {
                strategy: ApplyStrategy::Parallel,
                host_ids,
                canary_host: None,
                steps,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("host-{}", i)).collect()
    }

    #[test]
    fn test_canary_strategy() {
        let plan = create_apply_plan(ApplyStrategy::Canary, hosts(4));

        assert_eq!(plan.strategy, ApplyStrategy::Canary);
        assert_eq!(plan.canary_host, Some("host-1".to_string()));
        assert_eq!(plan.steps.len(), 2);

        // First step: canary only
        assert_eq!(plan.steps[0].host_ids, vec!["host-1"]);
        assert!(plan.steps[0].is_canary);
        assert_eq!(plan.steps[0].max_concurrency, 1);

        // Second step: remaining hosts
        assert_eq!(
            plan.steps[1].host_ids,
            vec!["host-2", "host-3", "host-4"]
        );
        assert!(!plan.steps[1].is_canary);
    }

    #[test]
    fn test_canary_single_host() {
        let plan = create_apply_plan(ApplyStrategy::Canary, hosts(1));

        assert_eq!(plan.canary_host, Some("host-1".to_string()));
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0].is_canary);
    }

    #[test]
    fn test_rolling_strategy() {
        let plan = create_apply_plan(ApplyStrategy::Rolling, hosts(3));

        assert_eq!(plan.strategy, ApplyStrategy::Rolling);
        assert_eq!(plan.canary_host, None);
        assert_eq!(plan.steps.len(), 3);

        for (i, step) in plan.steps.iter().enumerate() {
            assert_eq!(step.host_ids, vec![format!("host-{}", i + 1)]);
            assert!(!step.is_canary);
            assert_eq!(step.max_concurrency, 1);
        }
    }

    #[test]
    fn test_parallel_strategy() {
        let plan = create_apply_plan(ApplyStrategy::Parallel, hosts(3));

        assert_eq!(plan.strategy, ApplyStrategy::Parallel);
        assert_eq!(plan.canary_host, None);
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(
            plan.steps[0].host_ids,
            vec!["host-1", "host-2", "host-3"]
        );
        assert_eq!(plan.steps[0].max_concurrency, 5);
    }

    #[test]
    fn test_parallel_concurrency_limit() {
        let plan = create_apply_plan(ApplyStrategy::Parallel, hosts(10));

        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].host_ids.len(), 10);
        assert_eq!(plan.steps[0].max_concurrency, 5);
    }

    #[test]
    fn test_empty_hosts() {
        let plan = create_apply_plan(ApplyStrategy::Canary, vec![]);
        assert!(plan.steps.is_empty());
        assert_eq!(plan.canary_host, None);

        let plan = create_apply_plan(ApplyStrategy::Rolling, vec![]);
        assert!(plan.steps.is_empty());

        let plan = create_apply_plan(ApplyStrategy::Parallel, vec![]);
        assert!(plan.steps.is_empty());
    }
}
