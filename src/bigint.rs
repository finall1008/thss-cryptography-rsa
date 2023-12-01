use std::cmp;
use std::ops;

use rand::Rng;

use crate::utils;
use once_cell::sync::Lazy;

#[derive(Clone, Debug, Eq)]
pub struct BigInt {
    pub value: Vec<u64>, // 从小到大
    pub length: usize,
}

impl BigInt {
    pub const VALUE_LEN: u64 = 32;
    pub const VALUE_MASK: u64 = (((1 as u64) << Self::VALUE_LEN as u64) - 1);
    pub const MAX_LEN: usize = 2048;

    pub fn from_hex(hex: &str) -> Result<Self, &'static str> {
        if hex.len() % 8 != 0 {
            return Err("String length is not multiplication of 8");
        }

        let length = hex.len() / 8;
        if length > Self::MAX_LEN {
            return Err("Input is longer than 2048 * 8 * 32 bits");
        }
        let mut res = Self::with_capacity(length + 1);
        res.length = length;

        for (i, c) in hex.chars().enumerate() {
            let value_idx = length - 1 - i / 8;
            res.value[value_idx] *= 16;
            res.value[value_idx] += match c {
                '0'..='9' => c as u64 - '0' as u64,
                'a'..='f' => c as u64 - 'a' as u64 + 10,
                _ => return Err("Invalid char in hex string"),
            }
        }
        Ok(res)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            value: vec![0; capacity],
            length: 1,
        }
    }
    pub fn from_slice(slice: &[u64]) -> Self {
        let idx;
        if slice.len() > Self::MAX_LEN {
            idx = slice.len() - Self::MAX_LEN;
        } else {
            idx = 0;
        }
        let value: Vec<u64> = slice[idx..].into();
        let len = value.len();
        Self { value, length: len }
    }
    pub fn rand(length: usize) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            value: (0..length)
                .map(|i| {
                    let val = rng.gen::<u32>() as u64;
                    // 确保最高 value 至少为 1，符合长度要求
                    if i != length - 1 || val > 0 {
                        val
                    } else {
                        1
                    }
                })
                .collect(),
            length,
        }
    }
    pub fn is_zero(&self) -> bool {
        self.length == 1 && self.value[0] == 0
    }
    pub fn bitlen(&self) -> usize {
        (self.length - 1) * Self::VALUE_LEN as usize
            + utils::count_bits(self.value[self.length - 1])
    }
    pub fn to_int(&self) -> Result<u64, &str> {
        let mut res: u64 = 0;
        for i in 0..self.length {
            let val = self.value[i] * (1 << (i * Self::VALUE_LEN as usize)) as u64;
            if std::u64::MAX - res < val {
                return Err("overflow");
            }
            res += val;
        }
        Ok(res)
    }
    pub fn clone_slice(&self, start: usize, end: usize) -> Self {
        let new_value = self.value[start..end].into();
        Self {
            value: new_value,
            length: end - start,
        }
    }
    pub fn fmt_hex(&self) -> String {
        self.value[0..self.length]
            .iter()
            .rev()
            .map(|v| format!("{:08x}", v))
            .collect::<Vec<_>>()
            .join("")
    }
    pub fn print_hex(&self) {
        println!("{}", self.fmt_hex());
    }
    /// 巴雷特取模中的 m
    pub fn barrett_m(&self) -> Self {
        let k = 2 * self.bitlen();
        &(&Self::from_slice(&[1]) << k as u64) / self
    }

    fn remove_front_zeros(&mut self) {
        while self.length > 1 && self.value[self.length - 1] == 0 {
            self.length -= 1;
        }
    }
}

impl cmp::PartialEq for BigInt {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length && self.value[..self.length] == other.value[..self.length]
    }
}

impl cmp::PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self.length != other.length {
            return Some(cmp::Ord::cmp(&self.length, &other.length));
        }
        for i in (0..self.length).rev() {
            if self.value[i] != other.value[i] {
                return Some(cmp::Ord::cmp(&self.value[i], &other.value[i]));
            }
        }
        Some(cmp::Ordering::Equal)
    }
}

impl cmp::Ord for BigInt {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        cmp::PartialOrd::partial_cmp(&self, &other).unwrap()
    }
}

impl ops::Add<&BigInt> for &BigInt {
    type Output = BigInt;
    fn add(self, rhs: &BigInt) -> Self::Output {
        let res_length = std::cmp::max(self.length, rhs.length);
        let mut res = BigInt::with_capacity(res_length + 3);
        res.length = res_length;
        let get_val = |i, length, val: &Vec<u64>| {
            if i < length {
                val[i]
            } else {
                0
            }
        };

        for i in 0..res.length {
            let self_val = get_val(i, self.length, &self.value);
            let rhs_val = get_val(i, rhs.length, &rhs.value);
            let sum = res.value[i] + self_val + rhs_val;
            res.value[i + 1] = sum >> BigInt::VALUE_LEN;
            res.value[i] = sum & BigInt::VALUE_MASK;
        }
        if res.value[res.length] > 0 {
            res.length += 1;
        }
        res
    }
}

impl ops::Sub<&BigInt> for &BigInt {
    type Output = BigInt;
    fn sub(self, rhs: &BigInt) -> Self::Output {
        let mut res = BigInt::with_capacity(self.length + 1);
        res.length = self.length;
        let mut borrow: u64 = 0;

        for i in 0..self.length {
            let rhs_val;
            if i < rhs.length {
                rhs_val = rhs.value[i];
            } else {
                rhs_val = 0;
            }
            let self_val = self.value[i];

            if self_val < borrow || self_val - borrow < rhs_val {
                res.value[i] = self_val + (1 << BigInt::VALUE_LEN) - borrow - rhs_val;
                borrow = 1;
            } else {
                res.value[i] = self_val - borrow - rhs_val;
                borrow = 0;
            }
        }
        res.remove_front_zeros();
        res
    }
}

impl ops::Mul<&BigInt> for &BigInt {
    type Output = BigInt;
    fn mul(self, rhs: &BigInt) -> Self::Output {
        if self.is_zero() || rhs.is_zero() {
            return BigInt::with_capacity(1);
        }

        let mut res = BigInt::with_capacity(self.length + rhs.length + 1);
        res.length = self.length + rhs.length;
        for i in 0..self.length {
            for j in 0..rhs.length {
                res.value[i + j] += self.value[i] * rhs.value[j];
            }
            for j in i..res.length {
                res.value[j + 1] += res.value[j] >> BigInt::VALUE_LEN;
                res.value[j] &= BigInt::VALUE_MASK;
            }
        }

        res.remove_front_zeros();
        res
    }
}

impl ops::Mul<u64> for &BigInt {
    type Output = BigInt;
    fn mul(self, rhs: u64) -> Self::Output {
        if self.length == 0 || rhs == 0 {
            return BigInt::with_capacity(1);
        }

        let mut res = BigInt::with_capacity(self.length + 2);
        res.length = self.length;
        let mut extend: u64 = 0;
        for i in 0..self.length {
            let val = self.value[i] * rhs + extend;
            res.value[i] = val & BigInt::VALUE_MASK;
            extend = val >> BigInt::VALUE_LEN;
        }

        if extend != 0 {
            res.value[res.length] = extend;
            res.length += 1
        }
        res.remove_front_zeros();
        res
    }
}

impl ops::Div<&BigInt> for &BigInt {
    type Output = BigInt;
    fn div(self, rhs: &BigInt) -> Self::Output {
        let (res, _) = mod_div(self, rhs);
        res
    }
}

impl ops::Shr<u64> for &BigInt {
    type Output = BigInt;
    fn shr(self, shift: u64) -> Self::Output {
        let block_offset = (shift / BigInt::VALUE_LEN) as usize;
        let value_offset = (shift % BigInt::VALUE_LEN) as usize;
        let mut res = BigInt::with_capacity(self.length - block_offset + 2);
        res.length = self.length - block_offset;

        for i in block_offset..self.length {
            let mut next_value = if i + 1 < self.length {
                self.value[i + 1] & ((1 << value_offset as u64) - 1)
            } else {
                0
            };
            next_value =
                (next_value << (BigInt::VALUE_LEN - value_offset as u64)) & BigInt::VALUE_MASK;
            res.value[i - block_offset] = next_value + (self.value[i] >> value_offset as u64);
        }
        res.remove_front_zeros();
        res
    }
}

impl ops::Shl<u64> for &BigInt {
    type Output = BigInt;
    fn shl(self, shift: u64) -> Self::Output {
        let block_offset = (shift / BigInt::VALUE_LEN) as usize;
        let value_offset = (shift % BigInt::VALUE_LEN) as usize;
        let mut res = BigInt::with_capacity(self.length + block_offset + 6);
        res.length = self.length + block_offset;

        for i in block_offset..self.length + block_offset {
            let this_value = self.value[i - block_offset]
                & ((1 << (BigInt::VALUE_LEN - value_offset as u64)) - 1);
            let next_value =
                self.value[i - block_offset] >> (BigInt::VALUE_LEN - value_offset as u64);
            res.value[i] |= (this_value << value_offset) & BigInt::VALUE_MASK;
            res.value[i + 1] |= next_value;
        }
        while res.value[res.length] > 0 {
            res.length += 1;
        }
        res.remove_front_zeros();
        res
    }
}

pub fn mod_div(x: &BigInt, y: &BigInt) -> (BigInt, BigInt) {
    if x >= y {
        let mut res = BigInt::with_capacity(x.length);
        let mut remain = x.clone_slice(x.length - y.length + 1, x.length);

        for i in (0..x.length - y.length + 1).rev() {
            let mut lower: u64 = 0;
            let mut upper = BigInt::VALUE_MASK;

            res.value[i] = 0;
            remain = &remain << BigInt::VALUE_LEN;
            remain.value[0] = x.value[i];

            while lower <= upper {
                let mid = (lower + upper) >> 1;
                if y * mid <= remain {
                    res.value[i] = mid;
                    lower = mid + 1;
                } else {
                    upper = mid - 1;
                }
            }
            remain = &remain - &(y * res.value[i]);
        }

        res.length = x.length;
        res.remove_front_zeros();
        (res, remain)
    } else {
        (BigInt::with_capacity(1), x.clone())
    }
}

pub static ONE: Lazy<BigInt> = Lazy::new(|| BigInt::from_slice(&[1]));
pub static TWO: Lazy<BigInt> = Lazy::new(|| BigInt::from_slice(&[2]));
pub static THREE: Lazy<BigInt> = Lazy::new(|| BigInt::from_slice(&[3]));
