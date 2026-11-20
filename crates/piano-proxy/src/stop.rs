//! Ending the relay's long-lived work when the process terminates.

use pingora_error::ErrorType;
use tokio::sync::watch;

/// Error type of a request ended because the process terminates.
pub const TERMINATED: ErrorType = ErrorType::new("Terminated");

/// Set once the process terminates, as opposed to handing its listeners to a new
/// process. Media streams then end at once: they would not finish within the shutdown
/// timeout anyway, and a player resumes from the new process as soon as it listens.
#[derive(Debug)]
pub struct Stop {
    terminating: watch::Sender<bool>,
}

impl Default for Stop {
    fn default() -> Self {
        Self {
            terminating: watch::Sender::new(false),
        }
    }
}

impl Stop {
    pub fn terminate(&self) {
        self.terminating.send_replace(true);
    }

    pub fn is_terminating(&self) -> bool {
        *self.terminating.borrow()
    }

    /// A receiver whose `wait_for(|t| *t)` resolves once terminating.
    pub(crate) fn watch(&self) -> watch::Receiver<bool> {
        self.terminating.subscribe()
    }
}
