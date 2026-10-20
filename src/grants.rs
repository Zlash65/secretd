use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::process::{ProcessIdentity, same_process};

pub const MAX_GRANT_SECONDS: u64 = 60 * 60;
pub const DEFAULT_GRANT_SECONDS: u64 = 30 * 60;
pub const GRANT_EXTENSION_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug)]
pub struct Grant {
    pub id: String,
    pub resource: String,
    pub process: ProcessIdentity,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn add(
        &mut self,
        resource: String,
        process: ProcessIdentity,
        seconds: u64,
    ) -> Result<Grant, String> {
        if seconds == 0 || seconds > MAX_GRANT_SECONDS {
            return Err(format!(
                "Grant duration must be between 1 and {MAX_GRANT_SECONDS} seconds"
            ));
        }
        // A new grant for the same secret and process replaces the old one, so there is one
        // grant to revoke.
        self.grants
            .retain(|grant| grant.resource != resource || !same_process(&grant.process, &process));
        let now = now_millis();
        let grant = Grant {
            id: Uuid::new_v4().to_string(),
            resource,
            process,
            created_at: now,
            expires_at: now.saturating_add(seconds.saturating_mul(1_000)),
        };
        self.grants.push(grant.clone());
        Ok(grant)
    }

    pub fn find(&mut self, secret: &str, process_tree: &[ProcessIdentity]) -> Option<Grant> {
        self.cleanup();
        process_tree.iter().find_map(|process| {
            self.grants
                .iter()
                .rev()
                .find(|grant| grant.resource == secret && same_process(&grant.process, process))
                .cloned()
        })
    }

    pub fn list(&mut self) -> Vec<Grant> {
        self.cleanup();
        let mut grants = self.grants.clone();
        grants.sort_by_key(|grant| grant.expires_at);
        grants
    }

    pub fn revoke(&mut self, id: &str) -> Option<Grant> {
        let index = self.grants.iter().position(|grant| grant.id == id)?;
        Some(self.grants.remove(index))
    }

    pub fn extend(&mut self, id: &str) -> Option<Grant> {
        self.cleanup();
        let now = now_millis();
        let grant = self.grants.iter_mut().find(|grant| grant.id == id)?;
        grant.expires_at = grant
            .expires_at
            .saturating_add(GRANT_EXTENSION_SECONDS.saturating_mul(1_000))
            .min(now.saturating_add(MAX_GRANT_SECONDS.saturating_mul(1_000)));
        Some(grant.clone())
    }

    fn cleanup(&mut self) {
        let now = now_millis();
        self.grants.retain(|grant| grant.expires_at > now);
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            ppid: 1,
            started_at: "start".into(),
            executable: "/bin/tool".into(),
            command: "tool".into(),
        }
    }

    #[test]
    fn a_new_grant_replaces_one_for_the_same_secret_and_process() {
        let mut store = GrantStore::default();
        let shell = ProcessIdentity {
            pid: 10,
            ppid: 1,
            started_at: "start".into(),
            executable: "/bin/zsh".into(),
            command: "zsh".into(),
        };
        store.add("deploy/token".into(), shell.clone(), 60).unwrap();
        let replacement = store
            .add("deploy/token".into(), shell.clone(), 120)
            .unwrap();
        store.add("other/token".into(), shell, 60).unwrap();

        let grants = store.list();
        assert_eq!(grants.len(), 2);
        assert!(grants.iter().any(|grant| grant.id == replacement.id));
    }

    #[test]
    fn matches_a_secret() {
        let mut grants = GrantStore::default();
        grants.add("aws/key".into(), process(), 30).unwrap();
        assert!(grants.find("aws/key", &[process()]).is_some());
        assert!(grants.find("aws/other", &[process()]).is_none());
    }

    #[test]
    fn a_grant_for_an_ancestor_matches_its_descendants() {
        let ancestor = process();
        let mut child = process();
        child.pid = 43;
        child.ppid = ancestor.pid;
        child.started_at = "child-start".into();
        child.executable = "/bin/child".into();
        let mut grants = GrantStore::default();
        grants.add("token".into(), ancestor.clone(), 30).unwrap();

        assert!(grants.find("token", &[child, ancestor]).is_some());
    }

    #[test]
    fn extensions_add_fifteen_minutes_and_cap_remaining_time_at_one_hour() {
        let mut grants = GrantStore::default();
        let grant = grants
            .add("token".into(), process(), DEFAULT_GRANT_SECONDS)
            .unwrap();
        let first = grants.extend(&grant.id).unwrap();
        let second = grants.extend(&grant.id).unwrap();
        let third = grants.extend(&grant.id).unwrap();

        assert_eq!(first.expires_at, grant.expires_at + 15 * 60 * 1_000);
        assert_eq!(second.expires_at, grant.expires_at + 30 * 60 * 1_000);
        assert!(third.expires_at <= now_millis() + MAX_GRANT_SECONDS * 1_000);
    }
}
