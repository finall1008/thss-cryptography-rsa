use crate::bigint::{BigInt, ONE, THREE, TWO};

use once_cell::sync::Lazy;

/// 巴雷特模乘，需要确保 x < mod_num^2
pub fn barrett_mod(x: &BigInt, m: &BigInt, mod_num: &BigInt) -> BigInt {
    if mod_num.is_zero() || x < mod_num {
        return x.clone();
    }

    let k = 2 * mod_num.bitlen() as u64;
    let tmp = &(x * m) >> k;
    let mut res = x - &(&tmp * mod_num);
    while res >= *mod_num {
        res = &res - mod_num;
    }
    res
}

pub fn mod_power(a: &BigInt, b: &BigInt, barrett_m: &BigInt, mod_num: &BigInt) -> BigInt {
    let mut res = BigInt::with_capacity(2);
    res.length = 1;
    res.value[0] = 1;

    for i in (0..b.length).rev() {
        let mut max_bit = BigInt::VALUE_LEN - 1;
        if i == b.length - 1 {
            while (1 << max_bit) & b.value[i] == 0 {
                max_bit -= 1;
            }
        }

        for j in (0..=max_bit).rev() {
            res = barrett_mod(&(&res * &res), barrett_m, mod_num);
            if (1 << j) & b.value[i] != 0 {
                res = barrett_mod(&(&res * a), barrett_m, mod_num);
            }
        }
    }
    res
}

/// 扩展模 `mod_num` 欧几里得算法，返回 `(gcd, u, v)`, `d = ua + vb`
pub fn extended_euclid(
    a: u64,
    b: u64,
    barrett_m: &BigInt,
    mod_num: &BigInt,
) -> (u64, BigInt, BigInt) {
    if b != 0 {
        let q = a / b;
        let r = a % b;
        let (d, mut u, v) = extended_euclid(b, r, barrett_m, mod_num);
        let qv = barrett_mod(&(&v * q), barrett_m, mod_num);
        if u < qv {
            u = &u + &mod_num;
        }
        (d, v, barrett_mod(&(&u - &qv), barrett_m, mod_num))
    } else {
        (a, BigInt::from_slice(&[1]), BigInt::from_slice(&[0]))
    }
}

fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for i in 2..=n / 2 {
        if n % i == 0 {
            return false;
        }
    }
    true
}
fn small_primes() -> [u64; 1229] {
    let mut arr = [0; 1229];
    let mut i = 0;
    for n in 2..10000 {
        if is_prime(n) {
            arr[i] = n;
            i += 1;
        }
    }
    arr
}

pub fn miller_rabin(n: &BigInt) -> bool {
    const MR_TEST_TIMES: usize = 64;
    static SMALL_PRIMES: Lazy<[u64; 1229]> = Lazy::new(small_primes);

    // shortcuts
    if n == Lazy::force(&TWO) || n == Lazy::force(&THREE) {
        return true;
    }
    for small_prime in Lazy::force(&SMALL_PRIMES) {
        let mut base: u64 = 1;
        let mut sum: u64 = 0;
        for val in &n.value {
            sum += (base * (val % small_prime)) % small_prime;
            sum %= small_prime;
            base *= (BigInt::VALUE_MASK + 1) % small_prime;
            base %= small_prime;
        }
        if sum == 0 {
            return false;
        }
    }

    // n - 1 = 2^s * d
    let n_sub_1 = n - &ONE;
    let mut least_nozero_idx = 0;
    let mut s: u64 = 0;
    for (i, v) in n_sub_1.value[0..n_sub_1.length].iter().enumerate() {
        if *v != 0 {
            least_nozero_idx = i;
            break;
        } else {
            s += BigInt::VALUE_LEN;
        }
    }
    for i in 0..BigInt::VALUE_LEN {
        if (1 << i) & n_sub_1.value[least_nozero_idx] != 0 {
            s += i;
            break;
        }
    }
    let d = &n_sub_1 >> s;

    let barrett_m = n.barrett_m();
    for _ in 0..MR_TEST_TIMES {
        let mut a;
        loop {
            a = barrett_mod(&BigInt::rand(n.length), &barrett_m, n);
            if a != *ONE {
                break;
            }
        }
        // a^d
        let mut cond = mod_power(&a, &d, &barrett_m, n);
        if cond != *ONE && cond != n_sub_1 {
            let mut ok = false;
            for _ in 1..s {
                cond = barrett_mod(&(&cond * &cond), &barrett_m, n);
                if cond == n_sub_1 {
                    ok = true;
                    break;
                }
            }
            if !ok {
                return false;
            }
        }
    }
    true
}
