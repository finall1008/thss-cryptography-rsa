use std::time;

/// 返回 x 的最高非 0 位在哪一位上
pub fn count_bits(mut x: u64) -> usize {
    if x == 0 {
        return 1;
    }
    let mut ret: usize = 0;
    while x != 0 {
        ret += 1;
        x >>= 1;
    }
    ret
}

/// 返回 func 的执行用时，单位 us，及其返回值
pub fn count_time<F, Ret>(func: F) -> (u128, Ret)
where
    F: Fn() -> Ret,
{
    let timer = time::Instant::now();
    let ret = func();
    (timer.elapsed().as_micros(), ret)
}
