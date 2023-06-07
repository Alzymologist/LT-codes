#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use rand::distributions::{Uniform, WeightedIndex};

use crate::error::LTError;

pub const K_PARAM: usize = 500;
pub const DELTA_PARAM: f32 = 0.01;
pub const C_PARAM: f32 = 0.5;

pub struct Distributions {
    pub(crate) range_distribution: WeightedIndex<f32>,
    pub(crate) block_number_distribution: Uniform<usize>,
}

impl Distributions {
    pub(crate) fn calculate(n: usize) -> Result<Self, LTError> {
        let mut weights: Vec<f32> = Vec::with_capacity(K_PARAM);
        weights.push(1.0 / n as f32);
        for i in 1..K_PARAM {
            weights.push(1.0 / ((i as f32) * (i as f32 + 1.0)));
        }

        /*
            let k_param = {
                if n < K_PARAM {n}
                else {K_PARAM}
            };
            let r_param = C_PARAM * (k_param as f32 * DELTA_PARAM).ln() * (k_param as f32).sqrt();
            println!("{r_param}");

            let mut weights: Vec<f32> = Vec::with_capacity(k_param);
            weights.push(1.0 / n as f32);
            for i in 1..k_param {
                weights.push(1.0 / ((i as f32)*(i as f32 + 1.0)));
            }

            let mut t_weights: Vec<f32> = Vec::with_capacity(k_param);
            for i in 1..(k_param as f32/r_param) as usize {
                t_weights.push(r_param / (i as f32)*(k_param as f32))
            }
            t_weights.push(r_param * (r_param/DELTA_PARAM).ln() / k_param as f32);
            for _i in (k_param as f32/r_param) as usize .. k_param {
                t_weights.push(0.0)
            }

            for i in 0..k_param {
                weights[i] += t_weights[i];
            }
        */

        let range_distribution =
            WeightedIndex::new(&weights).map_err(|_| LTError::WeightedSettings)?;

        let block_number_distribution = Uniform::new(0, n);

        Ok(Self {
            range_distribution,
            block_number_distribution,
        })
    }
}
