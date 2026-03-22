/// Event name constants for Tauri event emission.
///
/// These match the event names documented in the IPC design section
/// of the architecture overview.
pub const EVENT_CONNECTION_STATUS: &str = "connection:status";
pub const EVENT_HIT_COUNTERS: &str = "activity:hit-counters";
pub const EVENT_BLOCKED: &str = "activity:blocked";
pub const EVENT_CONNTRACK: &str = "activity:conntrack";
pub const EVENT_SAFETY_TICK: &str = "safety:tick";
pub const EVENT_HOST_DRIFT: &str = "host:drift";
pub const EVENT_DETECT_PROGRESS: &str = "host:detect-progress";
