use core::fmt::Write as _;
use core::num::NonZeroUsize;
use std::sync::RwLock;
use std::time::Duration;

use libafl::{common::HasMetadata, Error};
use libafl_bolts::{
    current_time,
    rands::{Rand, StdRand},
};

use crate::feature_sched::features_map::{normalize_simplex_eps, EPS};
use crate::feature_sched::metadata::VecMaskRuntimeMeta;
use crate::feature_sched::{
    get_active_dim, get_v_candidates, push_v_candidate, replace_v_candidates, vecn_eq,
    TpeHistoryMeta,
};

const MAX_TRIALS: usize = 1024;
pub const INVERSE_LAMBDA: f64 = 0.5;

#[derive(Clone, Debug)]
pub struct TpeParams {
    pub gamma: f64,
    pub samples: usize,
    pub bw: f64,
    pub period: Duration,
    pub trials_threshold: usize,
    pub re_tpe_threshold: Duration,
}

impl Default for TpeParams {
    fn default() -> Self {
        Self {
            gamma: 0.15,
            samples: 16,
            bw: 0.05,
            period: Duration::from_secs(600),
            trials_threshold: 5,
            re_tpe_threshold: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TpeTrial {
    pub iteration: u64,
    pub vector: Vec<f64>,
    pub reward: f64,
    #[allow(dead_code)]
    pub active_start_ms: u64,
    pub active_end_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TpeState {
    pub trials: Vec<TpeTrial>,
    pub last_vec: Vec<f64>,
    pub lock_best: bool,
    pub best_fixed: Vec<f64>,
    pub restored_once: bool,
}

fn now_epoch_ms() -> u64 {
    current_time().as_millis() as u64
}

fn rand_gaussian(rng: &mut StdRand) -> f64 {
    let u1 = rng.next_float().clamp(f64::MIN_POSITIVE, 1.0);
    let u2 = rng.next_float();
    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * core::f64::consts::PI * u2;
    r * theta.cos()
}

pub fn alr(simplex_v: &[f64]) -> Vec<f64> {
    let w = normalize_simplex_eps(simplex_v).unwrap_or_else(|_| {
        if simplex_v.is_empty() {
            Vec::new()
        } else {
            vec![1.0 / simplex_v.len() as f64; simplex_v.len()]
        }
    });

    let k = w.len();
    if k <= 1 {
        return Vec::new();
    }

    let ref_w = w[k - 1].max(EPS);
    w[..k - 1]
        .iter()
        .map(|&wi| (wi.max(EPS) / ref_w).ln())
        .collect()
}

pub fn alr_inverse(u: &[f64]) -> Vec<f64> {
    if u.is_empty() {
        return vec![1.0];
    }

    let mut z = Vec::with_capacity(u.len() + 1);
    z.extend_from_slice(u);
    z.push(0.0);

    softmax(&z)
}

pub fn softmax(z: &[f64]) -> Vec<f64> {
    if z.is_empty() {
        return Vec::new();
    }
    let max_z = z.iter().copied().fold(f64::NEG_INFINITY, |a, b| a.max(b));
    let mut exps = z.iter().map(|v| (v - max_z).exp()).collect::<Vec<_>>();
    let sum = exps.iter().copied().sum::<f64>();
    if !sum.is_finite() || sum <= 0.0 {
        return vec![1.0 / z.len() as f64; z.len()];
    }
    for v in &mut exps {
        *v /= sum;
    }
    exps
}

pub fn logistic_normal_sample(center_simplex: &[f64], bw: f64, rng: &mut StdRand) -> Vec<f64> {
    let center = normalize_simplex_eps(center_simplex).unwrap_or_else(|_| {
        if center_simplex.is_empty() {
            Vec::new()
        } else {
            vec![1.0 / center_simplex.len() as f64; center_simplex.len()]
        }
    });

    if center.len() <= 1 {
        return vec![1.0; center.len().max(1)];
    }

    let mut u = alr(&center);
    let h = bw.max(EPS);
    for x in &mut u {
        *x += h * rand_gaussian(rng);
    }

    alr_inverse(&u)
}

pub fn logistic_normal_log_pdf(x_simplex: &[f64], center_simplex: &[f64], bw: f64) -> f64 {
    if x_simplex.len() != center_simplex.len() || x_simplex.is_empty() {
        return f64::NEG_INFINITY;
    }

    if x_simplex.len() == 1 {
        return 0.0;
    }

    let h = bw.max(EPS);
    let x = alr(x_simplex);
    let c = alr(center_simplex);

    if x.len() != c.len() {
        return f64::NEG_INFINITY;
    }

    let d = x.len() as f64;
    let sq = x
        .iter()
        .zip(c.iter())
        .map(|(a, b)| {
            let z = (a - b) / h;
            z * z
        })
        .sum::<f64>();

    -0.5 * sq - d * h.ln() - 0.5 * d * (2.0 * core::f64::consts::PI).ln()
}

pub fn kde_log_pdf(x_simplex: &[f64], centers: &[Vec<f64>], bw: f64) -> f64 {
    if centers.is_empty() {
        return f64::NEG_INFINITY;
    }
    let vals = centers
        .iter()
        .map(|c| logistic_normal_log_pdf(x_simplex, c, bw))
        .collect::<Vec<_>>();
    let max_v = vals
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, |a, b| a.max(b));
    if !max_v.is_finite() {
        return f64::NEG_INFINITY;
    }
    let sum = vals.iter().map(|v| (v - max_v).exp()).sum::<f64>();
    max_v + sum.ln() - (centers.len() as f64).ln()
}

pub fn sample_one_from_kde(centers: &[Vec<f64>], bw: f64, rng: &mut StdRand) -> Option<Vec<f64>> {
    if centers.is_empty() {
        return None;
    }
    let idx = rng.below(NonZeroUsize::new(centers.len()).unwrap());
    Some(logistic_normal_sample(&centers[idx], bw, rng))
}

pub fn inverse_simplex(best: &[f64]) -> Vec<f64> {
    let inv = best
        .iter()
        .map(|&w| 1.0 / (w.max(0.0) + EPS).powf(INVERSE_LAMBDA))
        .collect::<Vec<_>>();
    normalize_simplex_eps(&inv).unwrap_or_else(|_| vec![1.0 / best.len().max(1) as f64; best.len()])
}

fn normalize_simplex_exact(v: &[f64]) -> Result<Vec<f64>, Error> {
    if v.is_empty() {
        return Ok(Vec::new());
    }
    let mut sum = 0.0;
    for (idx, &value) in v.iter().enumerate() {
        if !value.is_finite() {
            return Err(Error::illegal_argument(format!(
                "BOFuzz vector error: non-finite simplex weight at index {}",
                idx
            )));
        }
        if value < 0.0 {
            return Err(Error::illegal_argument(format!(
                "BOFuzz vector error: negative simplex weight at index {}",
                idx
            )));
        }
        sum += value;
    }
    if !sum.is_finite() || sum <= 0.0 {
        return Err(Error::illegal_argument(
            "BOFuzz vector error: simplex denominator is zero".to_string(),
        ));
    }
    Ok(v.iter().map(|value| *value / sum).collect())
}

pub struct TpeOptimizer {
    pub params: TpeParams,
    pub state: RwLock<TpeState>,
}

impl TpeOptimizer {
    pub fn new(params: TpeParams) -> Self {
        Self {
            params,
            state: RwLock::new(TpeState::default()),
        }
    }

    pub fn restore_once<S: HasMetadata>(&self, state: &S) {
        let mut s = self.state.write().unwrap();
        if s.restored_once {
            return;
        }
        s.restored_once = true;
        if let Some(meta) = state.metadata_map().get::<TpeHistoryMeta>() {
            s.trials.clear();
            for (i, (v, r, ts)) in meta.trials.iter().enumerate() {
                if let Ok(simplex) = normalize_simplex_eps(v) {
                    s.trials.push(TpeTrial {
                        iteration: i as u64,
                        vector: simplex,
                        reward: *r,
                        active_start_ms: *ts,
                        active_end_ms: *ts,
                    });
                }
            }
            s.last_vec = normalize_simplex_eps(&meta.last_vec).unwrap_or_default();
        }
    }

    pub fn set_last_vec(&self, v: &[f64]) {
        let mut s = self.state.write().unwrap();
        s.last_vec = normalize_simplex_eps(v).unwrap_or_else(|_| v.to_vec());
    }

    #[allow(dead_code)]
    pub fn last_vec(&self) -> Vec<f64> {
        self.state.read().unwrap().last_vec.clone()
    }

    pub fn is_locked(&self) -> bool {
        self.state.read().unwrap().lock_best
    }

    pub fn lock_best(&self) {
        let best = self.best_by_reward().or_else(|| {
            let s = self.state.read().unwrap();
            if s.last_vec.is_empty() {
                None
            } else {
                Some(s.last_vec.clone())
            }
        });
        let mut s = self.state.write().unwrap();
        if let Some(best) = best {
            s.best_fixed = best;
        }
        s.lock_best = true;
    }

    pub fn unlock(&self) {
        self.state.write().unwrap().lock_best = false;
    }

    pub fn best_vec(&self) -> Option<Vec<f64>> {
        let s = self.state.read().unwrap();
        if !s.best_fixed.is_empty() {
            Some(s.best_fixed.clone())
        } else {
            drop(s);
            self.best_by_reward()
        }
    }

    pub fn observe_trial(
        &self,
        iteration: u64,
        vector: &[f64],
        reward: f64,
        active_start_ms: u64,
        active_end_ms: u64,
    ) {
        let Ok(vector) = normalize_simplex_eps(vector) else {
            return;
        };
        let mut s = self.state.write().unwrap();
        if let Some(last) = s.trials.last_mut() {
            if last.iteration == iteration || vecn_eq(&last.vector, &vector, 1e-6) {
                if reward > last.reward {
                    last.reward = reward;
                    last.active_end_ms = active_end_ms;
                }
                return;
            }
        }
        s.trials.push(TpeTrial {
            iteration,
            vector,
            reward,
            active_start_ms,
            active_end_ms,
        });
        if s.trials.len() > MAX_TRIALS {
            let drop_n = s.trials.len() - MAX_TRIALS;
            s.trials.drain(0..drop_n);
        }
    }

    pub fn enqueue_exact_then_neighbor_candidates<S: HasMetadata>(
        &self,
        state: &mut S,
        exact_center: &[f64],
        rng: &mut StdRand,
    ) -> Result<(), Error> {
        let active_dim = get_active_dim(state);
        if exact_center.len() != active_dim {
            return Err(Error::illegal_argument(format!(
                "BOFuzz vector error: exact center length {} != active_dim {}",
                exact_center.len(),
                active_dim
            )));
        }
        if active_dim == 0 {
            return Ok(());
        }

        let exact_normalized_center = normalize_simplex_exact(exact_center)?;
        push_v_candidate(state, exact_normalized_center.clone());
        self.enqueue_samples_around(state, &exact_normalized_center, self.params.samples, rng);
        Ok(())
    }

    pub fn enqueue_samples_around<S: HasMetadata>(
        &self,
        state: &mut S,
        center: &[f64],
        count: usize,
        rng: &mut StdRand,
    ) {
        for _ in 0..count.max(1) {
            let cand = logistic_normal_sample(center, self.params.bw, rng);
            push_v_candidate(state, cand);
        }
    }

    pub fn enqueue_inverse_candidates<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) {
        if let Some(best) = self.best_vec() {
            let inv = inverse_simplex(&best);
            self.enqueue_samples_around(state, &inv, self.params.samples, rng);
            self.unlock();
        }
    }

    pub fn next_untried_from_pool<S: HasMetadata>(&self, state: &mut S) -> Option<Vec<f64>> {
        let hist = self
            .state
            .read()
            .unwrap()
            .trials
            .iter()
            .map(|t| t.vector.clone())
            .collect::<Vec<_>>();
        let mut pool = get_v_candidates(state);
        while let Some(front) = pool.first() {
            let seen = hist
                .iter()
                .any(|h| h.len() == front.len() && vecn_eq(h, front, 1e-3));
            if seen {
                pool.remove(0);
            } else {
                break;
            }
        }
        let out = if pool.is_empty() {
            None
        } else {
            let raw = pool.remove(0);
            normalize_simplex_eps(&raw).ok()
        };
        replace_v_candidates(state, pool);
        out
    }

    fn init_candidate<S: HasMetadata>(&self, state: &mut S, rng: &mut StdRand) -> Option<Vec<f64>> {
        if let Some(v) = self.next_untried_from_pool(state) {
            return Some(v);
        }

        let active_dim = get_active_dim(state);
        if active_dim == 0 {
            return None;
        }

        let center = state
            .metadata_map()
            .get::<VecMaskRuntimeMeta>()
            .map(|m| m.normalized_credit_init_v.clone())
            .filter(|v| v.len() == active_dim)
            .and_then(|v| normalize_simplex_eps(&v).ok())
            .unwrap_or_else(|| vec![1.0 / active_dim as f64; active_dim]);

        Some(logistic_normal_sample(&center, self.params.bw, rng))
    }

    pub fn suggest_next<S: HasMetadata>(
        &self,
        state: &mut S,
        rng: &mut StdRand,
    ) -> Option<Vec<f64>> {
        if self.is_locked() {
            return None;
        }

        if let Some(v) = self.next_untried_from_pool(state) {
            return Some(v);
        }

        let Some((good, bad)) = self.split_good_bad() else {
            return self.init_candidate(state, rng);
        };

        let mut best_candidate: Option<Vec<f64>> = None;
        let mut best_score = f64::NEG_INFINITY;

        for _ in 0..self.params.samples.max(1) {
            let Some(candidate) = sample_one_from_kde(&good, self.params.bw, rng) else {
                continue;
            };

            let log_l = kde_log_pdf(&candidate, &good, self.params.bw);
            let log_g = kde_log_pdf(&candidate, &bad, self.params.bw);
            let score = log_l - log_g;

            if score.is_finite() && score > best_score {
                best_score = score;
                best_candidate = Some(candidate);
            }
        }

        if best_score.is_finite() && best_score > 0.0 {
            best_candidate
        } else {
            self.lock_best();
            None
        }
    }

    #[allow(clippy::type_complexity)]
    fn split_good_bad(&self) -> Option<(Vec<Vec<f64>>, Vec<Vec<f64>>)> {
        let s = self.state.read().unwrap();

        if s.trials.len() < self.params.trials_threshold.max(2) {
            return None;
        }

        let mut trials = s.trials.clone();
        trials.sort_by(|a, b| {
            b.reward
                .partial_cmp(&a.reward)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let k = ((trials.len() as f64 * self.params.gamma).ceil() as usize)
            .clamp(1, trials.len());

        let threshold = trials[k - 1].reward;

        let mut good = Vec::new();
        let mut bad = Vec::new();

        for t in &s.trials {
            if t.reward >= threshold {
                good.push(t.vector.clone());
            } else {
                bad.push(t.vector.clone());
            }
        }

        if good.is_empty() || bad.is_empty() {
            None
        } else {
            Some((good, bad))
        }
    }

    fn best_by_reward(&self) -> Option<Vec<f64>> {
        self.state
            .read()
            .unwrap()
            .trials
            .iter()
            .max_by(|a, b| a.reward.partial_cmp(&b.reward).unwrap())
            .map(|t| t.vector.clone())
    }

    pub fn persist_to_meta<S: HasMetadata>(&self, state: &mut S) {
        let s = self.state.read().unwrap();
        let meta = state
            .metadata_map_mut()
            .get_or_insert_with::<TpeHistoryMeta>(Default::default);
        meta.trials.clear();
        for t in &s.trials {
            meta.trials
                .push((t.vector.clone(), t.reward, t.active_end_ms));
        }
        meta.max_trials = MAX_TRIALS;
        meta.last_vec = s.last_vec.clone();
        meta.last_check_ms = Some(now_epoch_ms());
    }

    pub fn snapshot_trials_text(&self) -> String {
        let s = self.state.read().unwrap();
        let mut out = String::new();
        let _ = writeln!(&mut out, "[tpe-trials] count={}", s.trials.len());
        for (i, t) in s.trials.iter().enumerate() {
            let vv = t
                .vector
                .iter()
                .map(|x| format!("{:.4}", x))
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                &mut out,
                "[tpe-trial #{i}] iteration={} reward=ΔEdges={:.3} simplex=[{}] len={}",
                t.iteration,
                t.reward,
                vv,
                t.vector.len()
            );
        }
        out
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_sched::{set_schema_info, FeatureSpec};
    use libafl::common::HasMetadata;
    use libafl::state::NopState;
    use libafl_bolts::rands::StdRand;

    fn assert_close(actual: &[f64], expected: &[f64], eps: f64) {
        assert_eq!(actual.len(), expected.len());
        for (idx, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
            assert!(
                (a - e).abs() <= eps,
                "index {idx}: actual {a} != expected {e}"
            );
        }
    }

    fn assert_valid_simplex(v: &[f64], expected_len: usize) {
        assert_eq!(v.len(), expected_len);
        assert!(v.iter().all(|x| x.is_finite() && *x >= 0.0));
        let sum = v.iter().copied().sum::<f64>();
        assert!((sum - 1.0).abs() <= 1e-6, "simplex sum was {sum}");
    }

    fn contains_vec(vectors: &[Vec<f64>], needle: &[f64]) -> bool {
        vectors.iter().any(|v| vecn_eq(v, needle, 1e-6))
    }

    fn test_state(active_dim: usize, init_v: Vec<f64>) -> NopState<()> {
        let mut state = NopState::<()>::new();
        let features = (0..active_dim)
            .map(|idx| FeatureSpec {
                id: format!("f{idx}"),
                name: format!("feature_{idx}"),
                group: None,
                aliases: None,
            })
            .collect::<Vec<_>>();
        set_schema_info(
            &mut state,
            4,
            features.clone(),
            vec![true; active_dim],
            features.clone(),
        );
        state.add_metadata(VecMaskRuntimeMeta {
            mask_committed: true,
            tpe_init_committed: true,
            effective_mask: vec![true; active_dim],
            selected_feature_names: features.iter().map(|f| f.name.clone()).collect(),
            selected_schema_indices: (0..active_dim).collect(),
            normalized_credit_init_v: init_v,
            ..Default::default()
        });
        state
    }

    fn optimizer(gamma: f64, samples: usize, trials_threshold: usize) -> TpeOptimizer {
        TpeOptimizer::new(TpeParams {
            gamma,
            samples,
            trials_threshold,
            bw: 0.05,
            ..Default::default()
        })
    }

    fn push_trial(opt: &TpeOptimizer, iteration: u64, vector: Vec<f64>, reward: f64) {
        opt.state.write().unwrap().trials.push(TpeTrial {
            iteration,
            vector,
            reward,
            active_start_ms: 0,
            active_end_ms: 1,
        });
    }

    #[test]
    fn alr_inverse_round_trips_simplex() {
        let simplex = vec![0.2, 0.3, 0.5];
        let expected = normalize_simplex_eps(&simplex).unwrap();
        let u = alr(&simplex);
        let round_trip = alr_inverse(&u);

        assert_close(&round_trip, &expected, 1e-10);
    }

    #[test]
    fn alr_inverse_of_empty_returns_singleton_simplex() {
        assert_eq!(alr_inverse(&[]), vec![1.0]);
    }

    #[test]
    fn logistic_normal_sample_returns_valid_simplex() {
        let mut rng = StdRand::with_seed(7);
        let sample = logistic_normal_sample(&[0.2, 0.3, 0.5], 0.05, &mut rng);

        assert_valid_simplex(&sample, 3);
    }

    #[test]
    fn split_good_bad_includes_zero_reward_trials() {
        let opt = optimizer(0.5, 4, 4);
        let zero_reward = vec![0.2, 0.1, 0.7];
        push_trial(&opt, 0, vec![0.7, 0.2, 0.1], 10.0);
        push_trial(&opt, 1, vec![0.2, 0.7, 0.1], 5.0);
        push_trial(&opt, 2, zero_reward.clone(), 0.0);
        push_trial(&opt, 3, vec![0.4, 0.4, 0.2], 1.0);

        let (good, bad) = opt.split_good_bad().unwrap();

        assert_eq!(good.len() + bad.len(), 4);
        assert!(contains_vec(&bad, &zero_reward));
    }

    #[test]
    fn split_good_bad_returns_none_when_all_rewards_tied() {
        let opt = optimizer(0.5, 4, 2);
        push_trial(&opt, 0, vec![0.8, 0.2], 0.0);
        push_trial(&opt, 1, vec![0.2, 0.8], 0.0);

        assert!(opt.split_good_bad().is_none());
    }

    #[test]
    fn split_good_bad_uses_total_trial_threshold_not_positive_threshold() {
        let opt = optimizer(0.34, 4, 3);
        push_trial(&opt, 0, vec![0.8, 0.2], 2.0);
        push_trial(&opt, 1, vec![0.5, 0.5], 1.0);
        push_trial(&opt, 2, vec![0.2, 0.8], 0.0);

        let (good, bad) = opt.split_good_bad().unwrap();

        assert_eq!(good.len(), 2);
        assert_eq!(bad.len(), 1);
    }

    #[test]
    fn suggest_next_falls_back_to_init_candidate_when_split_unavailable() {
        let mut state = test_state(3, vec![0.2, 0.3, 0.5]);
        let opt = optimizer(0.5, 4, 5);
        let mut rng = StdRand::with_seed(11);

        let candidate = opt.suggest_next(&mut state, &mut rng).unwrap();

        assert_valid_simplex(&candidate, 3);
        assert!(!opt.is_locked());
    }

    #[test]
    fn suggest_next_locks_when_best_density_ratio_is_non_positive() {
        let mut state = test_state(2, vec![0.5, 0.5]);
        let opt = optimizer(0.5, 4, 2);
        push_trial(&opt, 0, vec![0.6, 0.4], 1.0);
        push_trial(&opt, 1, vec![0.6, 0.4], 0.0);
        let mut rng = StdRand::with_seed(13);

        assert!(opt.suggest_next(&mut state, &mut rng).is_none());
        assert!(opt.is_locked());
    }
}
