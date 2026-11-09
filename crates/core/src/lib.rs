//! Sweeps a Mac, GitHub repos and servers for known vulnerabilities with a coding agent.
//!
//! The app collects what is installed ([`Inventory`]), fetches advisories ([`Feeds`]:
//! OSV.dev, which includes the GitHub Advisory Database, plus NVD and CISA KEV), and hands
//! both to the user's chosen coding agent, which decides what is affected and, on approval,
//! fixes it. This crate holds all of that logic; the tray app and the CLI are thin front ends
//! over it.
//!
//! State lives in plain files under a [`DataDir`], configured by [`Config`].

mod agent;
mod bundle;
mod cancel;
mod config;
mod detect;
mod feeds;
mod findings;
mod fix;
mod github;
mod inventory;
mod lifecycle;
mod package;
mod paths;
mod popover;
mod server;
mod settings;
mod settings_view;
mod sweep;

pub use crate::agent::AgentError;
pub use crate::agent::AgentKind;
pub use crate::bundle::BundleError;
pub use crate::cancel::Cancel;
pub use crate::cancel::clean_up_interrupted;
pub use crate::config::Config;
pub use crate::config::ConfigProblem;
pub use crate::config::History;
pub use crate::config::LoadConfigError;
pub use crate::config::ModelName;
pub use crate::config::ParseModelNameError;
pub use crate::config::ParseRepoSlugError;
pub use crate::config::RemoteDir;
pub use crate::config::RepoSlug;
pub use crate::config::Schedule;
pub use crate::config::Server;
pub use crate::config::ServerName;
pub use crate::config::Since;
pub use crate::config::SshConn;
pub use crate::config::SshWord;
pub use crate::detect::Detected;
pub use crate::detect::detect;
pub use crate::feeds::Advisory;
pub use crate::feeds::Crowded;
pub use crate::feeds::FeedError;
pub use crate::feeds::Feeds;
pub use crate::feeds::Kev;
pub use crate::feeds::KeychainError;
pub use crate::feeds::NvdAccess;
pub use crate::feeds::OsvAdvisories;
pub use crate::feeds::OsvAdvisory;
pub use crate::feeds::OsvQuery;
pub use crate::feeds::ParseProductError;
pub use crate::feeds::Product;
pub use crate::feeds::Source;
pub use crate::findings::Confidence;
pub use crate::findings::Finding;
pub use crate::findings::Fix;
pub use crate::findings::Issue;
pub use crate::findings::Severity;
pub use crate::findings::Subject;
pub use crate::fix::Confirmed;
pub use crate::fix::FixError;
pub use crate::fix::FixPlan;
pub use crate::fix::FixRecord;
pub use crate::fix::Outcome;
pub use crate::fix::plan_fix;
pub use crate::fix::run_fix;
pub use crate::inventory::Component;
pub use crate::inventory::FoundIn;
pub use crate::inventory::Inventory;
pub use crate::inventory::InventoryError;
pub use crate::inventory::Lookup;
pub use crate::lifecycle::Changes;
pub use crate::lifecycle::Dismissal;
pub use crate::lifecycle::FindingKey;
pub use crate::lifecycle::Latest;
pub use crate::lifecycle::Open;
pub use crate::lifecycle::ParseFindingKeyError;
pub use crate::lifecycle::StateError;
pub use crate::lifecycle::dismiss;
pub use crate::lifecycle::last_sweep_started;
pub use crate::lifecycle::latest;
pub use crate::lifecycle::undismiss;
pub use crate::package::Ecosystem;
pub use crate::package::Package;
pub use crate::package::ParsePackageError;
pub use crate::paths::DataDir;
pub use crate::paths::InitError;
pub use crate::popover::PopoverView;
pub use crate::popover::popover_view;
pub use crate::popover::target_label;
pub use crate::settings::SaveSettingError;
pub use crate::settings::Setting;
pub use crate::settings::save_setting;
pub use crate::settings_view::SettingsView;
pub use crate::settings_view::settings_view;
pub use crate::sweep::Progress;
pub use crate::sweep::Report;
pub use crate::sweep::ReportFinding;
pub use crate::sweep::ReportIssue;
pub use crate::sweep::SweepError;
pub use crate::sweep::Targets;
pub use crate::sweep::alerts;
pub use crate::sweep::report_markdown;
pub use crate::sweep::sweep;
pub use crate::sweep::target_names;
