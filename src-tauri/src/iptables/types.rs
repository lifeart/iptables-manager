use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Top-level parsed output
// ---------------------------------------------------------------------------

/// Complete parsed representation of an `iptables-save` dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRuleset {
    /// One entry per table encountered (filter, nat, mangle, raw, security).
    pub tables: HashMap<String, TableState>,
    /// Lines that appeared before any table header (usually the generated-by comment).
    pub header_comments: Vec<String>,
}

/// State of a single iptables table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableState {
    pub name: String,
    pub chains: HashMap<String, ChainState>,
}

/// State of a single chain inside a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub name: String,
    /// Built-in chains have a policy (ACCEPT / DROP); user chains are `None`.
    pub policy: Option<String>,
    /// Counters on the chain declaration line, if present.
    pub counters: Option<(u64, u64)>,
    /// Rules appended to this chain, in order.
    pub rules: Vec<ParsedRule>,
    /// Detected owner of this chain.
    pub owner: ChainOwner,
}

// ---------------------------------------------------------------------------
// Parsed rule
// ---------------------------------------------------------------------------

/// A single rule line from `iptables-save`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRule {
    /// The original verbatim line (authoritative for unmodified rules).
    pub raw: String,
    /// Structured parse result. `None` when the line could not be parsed.
    pub parsed: Option<RuleSpec>,
    /// Warnings generated during parsing (e.g. unknown flags).
    pub warnings: Vec<String>,
    /// The chain this rule belongs to.
    pub chain: String,
    /// The table this rule belongs to.
    pub table: String,
}

// ---------------------------------------------------------------------------
// RuleSpec — structured representation of a parsed rule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub protocol: Option<Protocol>,
    pub protocol_negated: bool,
    pub source: Option<AddressSpec>,
    pub destination: Option<AddressSpec>,
    pub in_iface: Option<InterfaceSpec>,
    pub out_iface: Option<InterfaceSpec>,
    pub matches: Vec<MatchSpec>,
    pub target: Option<Target>,
    pub target_args: Vec<String>,
    pub comment: Option<String>,
    pub counters: Option<(u64, u64)>,
    pub fragment: Option<bool>,
    pub source_port: Option<PortSpec>,
    pub dest_port: Option<PortSpec>,
    pub address_family: AddressFamily,
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Gre,
    Esp,
    Ah,
    Sctp,
    All,
    Other(String),
}

impl Protocol {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tcp" | "6" => Protocol::Tcp,
            "udp" | "17" => Protocol::Udp,
            "icmp" | "1" => Protocol::Icmp,
            "icmpv6" | "ipv6-icmp" | "58" => Protocol::Icmpv6,
            "gre" | "47" => Protocol::Gre,
            "esp" | "50" => Protocol::Esp,
            "ah" | "51" => Protocol::Ah,
            "sctp" | "132" => Protocol::Sctp,
            "all" | "0" => Protocol::All,
            other => Protocol::Other(other.to_string()),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmpv6 => write!(f, "icmpv6"),
            Protocol::Gre => write!(f, "gre"),
            Protocol::Esp => write!(f, "esp"),
            Protocol::Ah => write!(f, "ah"),
            Protocol::Sctp => write!(f, "sctp"),
            Protocol::All => write!(f, "all"),
            Protocol::Other(s) => write!(f, "{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// AddressSpec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpec {
    pub addr: String,
    pub negated: bool,
}

// ---------------------------------------------------------------------------
// InterfaceSpec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSpec {
    pub name: String,
    pub negated: bool,
}

// ---------------------------------------------------------------------------
// PortSpec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSpec {
    /// A single port, e.g. `80`.
    Single(u16),
    /// Multiple ports, e.g. `80,443,8080`.
    Multi(Vec<u16>),
    /// A range, e.g. `1024:65535`.
    Range(u16, u16),
}

impl PortSpec {
    /// Parse a port specification string into a `PortSpec`.
    /// Supports single port ("80"), comma-separated ("80,443,8080"), and
    /// range with colon separator ("1024:65535").
    pub fn parse(s: &str) -> Option<PortSpec> {
        // Range: "1024:65535" or "1024-65535" (iptables uses : but some
        // contexts use -)
        if let Some(idx) = s.find(':') {
            let lo = s[..idx].parse::<u16>().ok()?;
            let hi = s[idx + 1..].parse::<u16>().ok()?;
            return Some(PortSpec::Range(lo, hi));
        }
        // Multi: "80,443,8080"
        if s.contains(',') {
            let ports: Option<Vec<u16>> = s.split(',').map(|p| p.parse::<u16>().ok()).collect();
            return ports.map(PortSpec::Multi);
        }
        // Single
        s.parse::<u16>().ok().map(PortSpec::Single)
    }
}

// ---------------------------------------------------------------------------
// AddressFamily
// ---------------------------------------------------------------------------

/// Whether the ruleset is for IPv4, IPv6, or both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    V4,
    V6,
    Both,
}

// ---------------------------------------------------------------------------
// MatchSpec — a loaded match module with its arguments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSpec {
    pub module: String,
    pub args: Vec<String>,
}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Accept,
    Drop,
    Reject,
    Log,
    Return,
    Dnat,
    Snat,
    Masquerade,
    Mark,
    ConntrackHelper,
    Queue,
    /// Jump to a user-defined chain.
    Jump(String),
    /// Any target we don't explicitly model.
    Other(String),
}

impl Target {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "ACCEPT" => Target::Accept,
            "DROP" => Target::Drop,
            "REJECT" => Target::Reject,
            "LOG" => Target::Log,
            "RETURN" => Target::Return,
            "DNAT" => Target::Dnat,
            "SNAT" => Target::Snat,
            "MASQUERADE" => Target::Masquerade,
            "MARK" => Target::Mark,
            "CT" => Target::ConntrackHelper,
            "QUEUE" => Target::Queue,
            other => {
                // Well-known extension targets — these are iptables target
                // extensions that are not user-defined chains.
                const EXTENSION_TARGETS: &[&str] = &[
                    "NFQUEUE", "NFLOG", "CLASSIFY", "CONNMARK", "TCPMSS",
                    "NOTRACK", "REDIRECT", "TPROXY", "TRACE", "SET",
                    "CLUSTERIP", "IDLETIMER", "AUDIT", "CHECKSUM", "NETMAP",
                    "TEE", "SECMARK",
                ];
                if EXTENSION_TARGETS.contains(&other) {
                    Target::Other(other.to_string())
                } else {
                    // Everything else is a jump to a user-defined chain.
                    Target::Jump(other.to_string())
                }
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Accept => write!(f, "ACCEPT"),
            Target::Drop => write!(f, "DROP"),
            Target::Reject => write!(f, "REJECT"),
            Target::Log => write!(f, "LOG"),
            Target::Return => write!(f, "RETURN"),
            Target::Dnat => write!(f, "DNAT"),
            Target::Snat => write!(f, "SNAT"),
            Target::Masquerade => write!(f, "MASQUERADE"),
            Target::Mark => write!(f, "MARK"),
            Target::ConntrackHelper => write!(f, "CT"),
            Target::Queue => write!(f, "QUEUE"),
            Target::Jump(name) => write!(f, "{}", name),
            Target::Other(name) => write!(f, "{}", name),
        }
    }
}

// ---------------------------------------------------------------------------
// Chain ownership
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainOwner {
    System(SystemTool),
    App,
    BuiltIn,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemTool {
    Docker,
    Fail2ban,
    Kubernetes,
    Csf,
    WgQuick,
    Ufw,
    Firewalld,
}

// ---------------------------------------------------------------------------
// ParseError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum ParseError {
    #[error("input exceeds 10MB limit ({size} bytes)")]
    InputTooLarge { size: usize },

    #[error("unexpected table state at line {line}: {message}")]
    InvalidState { line: usize, message: String },

    #[error("malformed line {line}: {message}")]
    MalformedLine { line: usize, message: String },
}
