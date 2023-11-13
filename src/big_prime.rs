#![allow(non_snake_case)]
use num_bigint::{BigInt};
use num_bigint::RandBigInt;
use num_traits::{cast::FromPrimitive};

pub fn gen_big_prime(n: u64) -> BigInt
{
    let first_primes = vec![
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103,
        107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257,
        263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349
    ];
    loop
    {
        let big_n = BigInt::from_u64(n).unwrap();
        let primeCandidate = getLowLevelPrime(big_n.clone(), first_primes.clone());
        if isMillerRabin(primeCandidate.clone())
        {
//          println!("{} bit prime is {}", n.clone(), primeCandidate.clone());
            break primeCandidate.clone();
        }
    }
}

fn nBitRand(n: BigInt) -> BigInt
{
    let big2 = BigInt::from_u64(2).unwrap();
    let big1 = BigInt::from_u64(1).unwrap();
    let lower = big_pow(big2.clone(), n.clone() - big1.clone()) + big1.clone();
    let higher = big_pow(big2.clone(), n.clone()) - big1.clone();
    return RandBigInt::gen_bigint_range(&mut rand::thread_rng(), &lower.clone(), &higher.clone());
}


    //really huge  numbers take a while but will work given enough time to loop
pub fn big_pow(base: BigInt, exp: BigInt) -> BigInt
{
    if exp == BigInt::from_u32(0).unwrap()
    {
        return BigInt::from_u32(1).unwrap();
    }
    let mut answer = base.clone();
    let mut i = BigInt::from_u32(1).unwrap();
    while i < exp
    {
        i = i + BigInt::from_u32(1).unwrap();
        answer = answer * base.clone();
    }
    return answer;
}

fn getLowLevelPrime(n: BigInt, first_primes: Vec<u64>) -> BigInt
{
    let answer: BigInt;
    loop
    {
        let random = nBitRand(n.clone());
        let big0 = BigInt::from_u64(0).unwrap();
        let big2 = BigInt::from_u64(2).unwrap();
        let mut is_prime = true;
        for d in first_primes.iter()
        {
            let bigd = BigInt::from_u64(*d).unwrap();
            if random.clone() % bigd.clone() == big0.clone() && big_pow(bigd.clone(), big2.clone()) <= random.clone()
            {
                is_prime =false;
                break;
            }
        }
        if is_prime
        {
            answer = random;
            break;
        }
    }
    return answer;
}

fn isMillerRabin(primeSuspect: BigInt) -> bool
{
    let big0 = BigInt::from_u64(0).unwrap();
    let big1 = BigInt::from_u64(1).unwrap();
    let big2 = BigInt::from_u64(2).unwrap();
    let mut maxDivsBy2 = 0;
    let mut edit = primeSuspect.clone() - big1.clone();
    while edit.clone() % 2 == big0.clone()
    {
        edit = edit >> 1;
        maxDivsBy2 += 1;
    }
    assert!(big_pow(big2.clone(), BigInt::from_u64(maxDivsBy2).unwrap()) * edit.clone() == primeSuspect.clone() - big1.clone());
    fn trialComposite(round_tester: BigInt, edit: BigInt, primeSuspect: BigInt, maxDivsBy2: u64) -> bool
    {
        if modexp_fast_internal_copy(round_tester.clone(), edit.clone(), primeSuspect.clone()) == BigInt::from_u32(1).unwrap()
        {
            return false;
        }
        for i in 0..maxDivsBy2
        {
            if modexp_fast_internal_copy(
               round_tester.clone(),
               big_pow(BigInt::from_u64(2).unwrap(), BigInt::from_u64(i).unwrap()) * edit.clone(),
               primeSuspect.clone()
            ) == primeSuspect.clone() - BigInt::from_u64(1).unwrap()
            {
                return false;
            }
        }
        return true;
    }
    let trials = 20;
    for _ in 0..trials
    {
        let round_tester = RandBigInt::gen_bigint_range(&mut rand::thread_rng(), &big2.clone(), &primeSuspect.clone());
        if trialComposite(round_tester.clone(), edit.clone(), primeSuspect.clone(), maxDivsBy2.clone())
        {
            return false
        }
    }
    return true;
}

pub fn modexp_fast_internal_copy(mut b: BigInt, mut e: BigInt, m: BigInt) -> BigInt
{
    let mut result = BigInt::from_u64(1).unwrap();
    let big1 = BigInt::from_u64(1).unwrap();
    let big2 = BigInt::from_u64(2).unwrap();
    while e > BigInt::from_u64(0).unwrap()
    {
        if e.clone() % big2.clone() == big1
        {
            result = (result.clone() * b.clone()) % m.clone();
        }
        b = (b.clone() * b.clone()) % m.clone();
        e = e.clone() / 2.clone();
    }
    result % m
}
