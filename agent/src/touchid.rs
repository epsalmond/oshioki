//! The Touch ID prompt, as a state machine with the macOS calls behind traits.
//!
//! On a Mac with an enclave key the signature is the approval: the sheet the
//! enclave shows before signing is the only prompt the operator sees. That puts
//! three timing rules in one place, and they are the reason this is a type and
//! not a few lines inside the request loop.
//!
//! * One sheet at a time. Two sheets would race for the same fingerprint and
//!   the operator could not tell which request they were answering.
//! * A locked screen shows nothing. The enclave reports a dismissed sheet and
//!   an absent operator identically, so a sheet raised against the lock screen
//!   would read as a denial nobody made.
//! * The request's deadline wins. When it passes, the sheet is invalidated and
//!   no verdict is published: the hook has already failed closed by then, and a
//!   verdict nobody gave would be a lie about a request nobody read.
//!
//! The traits keep the FFI out, so the rules above are tested on any platform.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::sync::Mutex;
use tracing::info;

use crate::remaining_until;

/// How often a waiting request re-checks a locked screen.
const LOCK_POLL: Duration = Duration::from_secs(1);

/// Reports whether this Mac's screen is locked.
pub trait ScreenLock: Send + Sync + 'static {
    fn is_locked(&self) -> bool;
}

/// Dismisses the Touch ID sheet currently on screen, if any.
///
/// Cancellations are numbered because a deadline timer cannot always be
/// stopped: aborting a task that has already reached its last few instructions
/// does nothing. A timer for a request that was just answered can still fire,
/// and an unnumbered cancellation would land on the next request instead,
/// tearing down a sheet nobody had seen and publishing a denial for it.
pub trait PromptCancel: Send + Sync + 'static {
    /// Starts an attempt and returns its number.
    fn begin(&self) -> u64;
    /// Dismisses that attempt's sheet, and only that attempt's.
    fn cancel(&self, attempt: u64);
}

/// Why an attempt produced no signature.
pub enum AttemptError {
    /// The sheet was dismissed, or nobody answered it.
    Canceled,
    /// The key or the enclave refused. Not an answer, and not retryable.
    Failed(anyhow::Error),
}

/// What one request's prompt came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Approved(T),
    Denied,
    /// The deadline passed with no answer. Publish nothing.
    Expired,
}

/// Serializes Touch ID sheets and enforces the request deadline around them.
pub struct TouchIdPrompt {
    screen: Box<dyn ScreenLock>,
    canceller: Arc<dyn PromptCancel>,
    poll: Duration,
    sheet: Mutex<()>,
}

impl TouchIdPrompt {
    pub fn new(screen: Box<dyn ScreenLock>, canceller: Arc<dyn PromptCancel>) -> Self {
        Self {
            screen,
            canceller,
            poll: LOCK_POLL,
            sheet: Mutex::new(()),
        }
    }

    /// Shortens the lock poll interval. Tests only; a real agent waits seconds.
    #[cfg(test)]
    fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Runs `sign` behind one Touch ID sheet and reports what came of it.
    ///
    /// `sign` blocks for the whole interaction, so it runs on a blocking
    /// thread. Waiting for an earlier sheet, and waiting for the screen to
    /// unlock, both happen before `sign` is called at all: a request whose
    /// deadline passes while it waits never raises a sheet.
    pub async fn ask<T, F>(&self, request_id: &str, expires_at: i64, sign: F) -> Result<Outcome<T>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, AttemptError> + Send + 'static,
    {
        let _sheet = self.sheet.lock().await;
        let mut waited_for_the_screen = false;
        let remaining = loop {
            let Some(remaining) = remaining_until(expires_at) else {
                if waited_for_the_screen {
                    info!(
                        request_id,
                        "the screen stayed locked until the request expired"
                    );
                }
                return Ok(Outcome::Expired);
            };
            if !self.screen.is_locked() {
                break remaining;
            }
            if !waited_for_the_screen {
                waited_for_the_screen = true;
                // Without this a machine with no window session, an ssh
                // session for instance, expires every request in silence.
                info!(
                    request_id,
                    "the screen is locked, so the Touch ID sheet waits for it to unlock"
                );
            }
            tokio::time::sleep(self.poll.min(remaining)).await;
        };
        if waited_for_the_screen {
            info!(
                request_id,
                "the screen unlocked, raising the Touch ID sheet"
            );
        }

        // The sheet blocks a thread that cannot see the clock, so the deadline
        // arrives from here: invalidating the context tears the sheet down.
        let expired = Arc::new(AtomicBool::new(false));
        let attempt = self.canceller.begin();
        let deadline = tokio::spawn({
            let expired = Arc::clone(&expired);
            let canceller = Arc::clone(&self.canceller);
            async move {
                tokio::time::sleep(remaining).await;
                expired.store(true, Ordering::SeqCst);
                canceller.cancel(attempt);
            }
        });
        let signed = tokio::task::spawn_blocking(sign).await;
        deadline.abort();

        let signed = signed.context("the Touch ID prompt thread panicked")?;
        // An answer that arrives after the deadline is not a verdict: the hook
        // stopped listening, and a late approval must not be published as one.
        if expired.load(Ordering::SeqCst) {
            return Ok(Outcome::Expired);
        }
        match signed {
            Ok(value) => Ok(Outcome::Approved(value)),
            Err(AttemptError::Canceled) => Ok(Outcome::Denied),
            Err(AttemptError::Failed(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AttemptError, Outcome, PromptCancel, ScreenLock, TouchIdPrompt};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    #[derive(Default)]
    struct Screen {
        locked: AtomicBool,
        polls: AtomicUsize,
    }

    impl Screen {
        fn locked() -> Arc<Self> {
            let screen = Arc::new(Self::default());
            screen.locked.store(true, Ordering::SeqCst);
            screen
        }
    }

    impl ScreenLock for Arc<Screen> {
        fn is_locked(&self) -> bool {
            self.polls.fetch_add(1, Ordering::SeqCst);
            self.locked.load(Ordering::SeqCst)
        }
    }

    /// Models the real canceller: an attempt number, and a flag the sheet
    /// checks when it comes up.
    #[derive(Default)]
    struct Canceller {
        state: std::sync::Mutex<(u64, bool)>,
        cancels: AtomicUsize,
    }

    impl Canceller {
        /// What the sheet sees when it is raised, as `arm` does on a Mac.
        fn cancelled(&self) -> bool {
            self.state.lock().unwrap().1
        }

        fn attempt(&self) -> u64 {
            self.state.lock().unwrap().0
        }
    }

    impl PromptCancel for Arc<Canceller> {
        fn begin(&self) -> u64 {
            let mut state = self.state.lock().unwrap();
            state.0 += 1;
            state.1 = false;
            state.0
        }

        fn cancel(&self, attempt: u64) {
            let mut state = self.state.lock().unwrap();
            if state.0 != attempt {
                return;
            }
            state.1 = true;
            self.cancels.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn prompt(screen: &Arc<Screen>, canceller: &Arc<Canceller>) -> TouchIdPrompt {
        TouchIdPrompt::new(
            Box::new(Arc::clone(screen)),
            Arc::new(Arc::clone(canceller)),
        )
        .with_poll(Duration::from_millis(10))
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    /// The ordinary path: the sheet is answered and the signature is the
    /// approval.
    #[tokio::test]
    async fn a_completed_signature_is_an_approval() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let outcome = prompt(&screen, &canceller)
            .ask("req-1", now() + 30, || Ok(vec![1_u8, 2, 3]))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Approved(vec![1, 2, 3]));
        assert_eq!(canceller.cancels.load(Ordering::SeqCst), 0);
    }

    /// A dismissed sheet is a denial, and the hook should hear it at once.
    #[tokio::test]
    async fn a_dismissed_sheet_denies() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let outcome: Outcome<Vec<u8>> = prompt(&screen, &canceller)
            .ask("req-1", now() + 30, || Err(AttemptError::Canceled))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Denied);
    }

    /// A broken key is not an answer. It has to reach the caller as an error so
    /// the operator is told to re-pair, and no verdict is published.
    #[tokio::test]
    async fn a_failed_signature_is_not_a_verdict() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let error = prompt(&screen, &canceller)
            .ask("req-1", now() + 30, || {
                Err::<Vec<u8>, _>(AttemptError::Failed(anyhow::anyhow!("biometry changed")))
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("biometry changed"));
    }

    /// A request that expired while it waited for an earlier sheet is never
    /// shown: nothing is signed and nothing is published.
    #[tokio::test]
    async fn an_expired_request_raises_no_sheet() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let outcome: Outcome<Vec<u8>> = prompt(&screen, &canceller)
            .ask("req-1", now() - 1, || panic!("the sheet must not appear"))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Expired);
    }

    /// A locked screen holds the sheet back until the operator is there to see
    /// it. The wait is a poll, so the request goes through as soon as it can.
    #[tokio::test]
    async fn a_locked_screen_delays_the_sheet_until_unlock() {
        let (screen, canceller) = (Screen::locked(), Arc::new(Canceller::default()));
        let unlock = tokio::spawn({
            let screen = Arc::clone(&screen);
            async move {
                tokio::time::sleep(Duration::from_millis(60)).await;
                screen.locked.store(false, Ordering::SeqCst);
            }
        });
        let outcome = prompt(&screen, &canceller)
            .ask("req-1", now() + 30, || Ok(vec![7_u8]))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Approved(vec![7]));
        assert!(screen.polls.load(Ordering::SeqCst) > 1);
        unlock.await.unwrap();
    }

    /// A screen still locked at the deadline denies nothing: the request dies
    /// unanswered, and the hook fails closed on its own.
    #[tokio::test]
    async fn a_screen_locked_past_the_deadline_yields_no_verdict() {
        let (screen, canceller) = (Screen::locked(), Arc::new(Canceller::default()));
        let outcome: Outcome<Vec<u8>> = prompt(&screen, &canceller)
            .ask("req-1", now() + 1, || panic!("the sheet must not appear"))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Expired);
    }

    /// The deadline reaches a sheet that is already up: the prompt is torn down
    /// and the cancellation it causes is a timeout, not a denial.
    #[tokio::test]
    async fn the_deadline_tears_down_a_waiting_sheet() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let (torn_down, sheet_gone) = std::sync::mpsc::channel();
        let watcher = Arc::clone(&canceller);
        let outcome: Outcome<Vec<u8>> = prompt(&screen, &canceller)
            .ask("req-1", now() + 1, move || {
                while watcher.cancels.load(Ordering::SeqCst) == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
                torn_down.send(()).unwrap();
                Err(AttemptError::Canceled)
            })
            .await
            .unwrap();
        sheet_gone.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(outcome, Outcome::Expired);
        assert_eq!(canceller.cancels.load(Ordering::SeqCst), 1);
    }

    /// A deadline timer for a request that was just answered can still fire:
    /// aborting a task in its last instructions does nothing. That cancel must
    /// not reach the next request, whose sheet nobody has seen yet.
    #[tokio::test]
    async fn a_late_cancel_from_a_finished_attempt_leaves_the_next_one_alone() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let prompt = prompt(&screen, &canceller);
        let outcome = prompt
            .ask("req-1", now() + 30, || Ok(vec![1_u8]))
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Approved(vec![1]));

        // The first request's timer, firing while the next request is already
        // under way. The sheet then checks the flag, as the enclave does when
        // it arms a fresh context.
        let stale = canceller.attempt();
        let watcher = Arc::clone(&canceller);
        let outcome = prompt
            .ask("req-2", now() + 30, move || {
                watcher.cancel(stale);
                if watcher.cancelled() {
                    return Err(AttemptError::Canceled);
                }
                Ok(vec![2_u8])
            })
            .await
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Approved(vec![2]),
            "a stale cancellation denied a request nobody was shown"
        );
    }

    /// Two requests at once share one fingerprint reader. The second sheet only
    /// appears after the first is answered.
    #[tokio::test]
    async fn only_one_sheet_is_up_at_a_time() {
        let (screen, canceller) = (Arc::new(Screen::default()), Arc::new(Canceller::default()));
        let prompt = Arc::new(prompt(&screen, &canceller));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut sheets = Vec::new();
        for _ in 0..4 {
            let (prompt, live, peak) = (Arc::clone(&prompt), Arc::clone(&live), Arc::clone(&peak));
            sheets.push(tokio::spawn(async move {
                prompt
                    .ask("req-1", now() + 30, move || {
                        let concurrent = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(concurrent, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        live.fetch_sub(1, Ordering::SeqCst);
                        Ok(vec![0_u8])
                    })
                    .await
                    .unwrap()
            }));
        }
        for sheet in sheets {
            assert_eq!(sheet.await.unwrap(), Outcome::Approved(vec![0]));
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }
}
