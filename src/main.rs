/* Working Name: rsElGamal | ElGamal Encryption Decryption and Key Generation Client
    Copyright (C) <2023>  <Ryan Berkovich>
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */
#![allow(non_snake_case)]
#![allow(unused_parens)]
use primal::{Sieve};
use ramp::{traits::Integer};
use std::{
    io::{Read, Write, LineWriter}, 
    path::Path, fs, 
    env, process::exit, fs::File, 
    str::FromStr
};
use num_bigint::{BigInt, ToBigInt, RandBigInt};
use num_traits::{cast::FromPrimitive, ToPrimitive};
fn main() 
{
    //To pick q(large cyclic group of prime order) generate n bit prime where n is >= 512
    //To pick g( pick randrange(2, q-1) and check if its within cyclic group q if so its a valid g
    //if not repick a rand number from the range
    //g needs to be known by both parties so will be public q as well,TODO: they should ideally check
    //these are primes before starting
    let qstr = "24203810936489328066547711667750107305261714914281111737465409072411360781912473629390035989284760774475351328169623492689358825716725322053633688962517752300713468965010218001785476619061243608516794275775259574466779369559551109409929965466188903169176545928414494211419486097672580732413464620776696654721315502309434102007050909879953004082937683105226142055332736787264339328539810852786809156578043499811001177790783336344925377101557840105513558508778558821871979111653966865503556094743822351152893808391024165885299519778722879162981089600296511241762712218864086216300212830853124558089728811378148635803099"; //2048 bit
    let q = qstr.parse::<BigInt>().unwrap();
    let g = gen_G(q.clone());
    //interesting new diffie hellman hardness assumption w ElGamal: https://eprint.iacr.org/2023/314.pdf
    let args: Vec<String> = env::args().collect();
    if args.len() < 2
    {
        println!("provide argument!\n Choices:\ngenPubKey\nencryptToPubKey\ndecryptFromPubKey");
    }
    else if args.len() >= 2
    {
        if args[1].to_string() == "genPubKey".to_string() //TODO:from specify q and g (for ElGamal "channel")
        {
            let (privKey, pubKey) = keyGen(q.clone(), g.clone());
            let filename: String;
            let mut i = 0;
            loop
            {
                let istr = i.to_string();
                if Path::new(&("Key".to_owned() + &istr + ".ElGamalKey")).exists() == false
                {
                    filename =  "Key".to_owned() + &istr + ".ElGamalKey";
                    break;
                }
                else
                {
                    i = i + 1;
                    continue
                }
            }
            let mut file = File::create(filename.clone()).expect("error setting up filehandle");
            let format ="{\n".to_owned() +
                            &"\t\"Public Key\": \"".to_owned() + &pubKey.to_string() + "\",\n" + 
                            &"\t\"Private Key\": \"" + &privKey.to_string() + "\",\n" +
                            &"\t\"q\": \"" + &q.to_string() + "\",\n" +
                            &"\t\"g\": \"" + &g.to_string() + "\"" + 
                        "\n}";
            file.write_all(format.as_bytes()).expect("error writing to file");
            println!("{}", filename);
        }
        else if args[1].to_string() == "encryptToPubKey".to_string()
        {
            if args.len() < 3
            {
                println!("enter counterparty's pubkey as followup arg to encryptToPubKey");
                exit(1);
            }
            else if args.len() < 4
            {
                println!("enter the pubkey filename you want to use to encrypt the message as a followup arg to counterpartys pubkey");
                exit(1);
            }
            else if args.len() < 5
            {
                println!("enter the message you want to encrypt as a followup arg to your pubkey");
                exit(1);
            }
            else if args.len() < 6
            {
                println!("enter the path to save the encryption to last");
                exit(1);
            }
            else
            {
                let receiver = &args[2].to_string().parse::<BigInt>().unwrap();
                let message = args[4].to_string();
                let myPubKeyStr = args[3].to_string(); //go into pubkey file find privatekey json key assign to q
                let path  = args[5].to_string();
                let mut file = File::open(myPubKeyStr.clone()).expect("cant find file");
                let mut contents = String::new();
                file.read_to_string(&mut contents).expect("error reading keyfile contents");
                let json: serde_json::Value =
                    serde_json::from_str(&contents).expect("JSON was not well-formatted");
                let privateKey = &json["Private Key"].as_str().unwrap().parse::<BigInt>().unwrap();
                                                    // https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
                let q = &json["q"].as_str().unwrap().parse::<BigInt>().unwrap();
                let encryption = encrypt(message.to_string(), q.clone(), receiver.clone(), privateKey.clone());
                let file = File::create(path).expect("err creating file");
                let mut file = LineWriter::new(file);
                let mut format = String::new();
                for line in encryption
                {
                    format.push_str(&(line.to_string() + "\n"));
                }
                let _result = file.write_all(format.as_bytes());
            }
        }
        else if args[1].to_string() == "decryptFromPubKey".to_string()
        {
            if args.len() < 3
            {
                println!("enter message(filename) to decrypt as followup to decryptFromPubKey arg");
                exit(1);
            }
            else if args.len() < 4
            {
                println!("enter the senders public key as a followup to the encrypted message arg");
                exit(1);
            }
            else if args.len() < 5
            {
                println!("enter your public key filename as a follow up to the senders public key arg");
                exit(1);
            }
            else
            {
                let EncryptedMsgFilename = args[2].to_string();
                let SenderPublicKey = &args[3].to_string().parse::<BigInt>().unwrap();
                let MyReceivingPubKey = args[4].to_string();
                let filename = MyReceivingPubKey.clone().to_string();
                let contents = fs::read_to_string(filename).expect("file not found");
                let j : serde_json::Value = serde_json::from_str(&contents).expect("JSON was not well-formatted");
                let MyPrivateDecryptionKey = &j["Private Key"].as_str().unwrap().parse::<BigInt>().unwrap();
//                dbg!(&EncryptedMsgFilename);
                let EncryptedMsg = fs::read_to_string(EncryptedMsgFilename).expect("file not found");
                let mut Encryption = Vec::<BigInt>::new();
                let mut currentline = String::new();
                for c in EncryptedMsg.chars()
                {
                    if c != '\n'
                    {
                        currentline.push(c);
                    }
                    else
                    {    
                        Encryption.push((&currentline).parse::<BigInt>().unwrap());
                        currentline = String::new();
                    }
                }
                let q = BigInt::from_str(&j["q"].as_str().unwrap()).unwrap();
                let decryption = String::from_iter(decrypt(Encryption, SenderPublicKey.clone(), MyPrivateDecryptionKey.clone(), q));
                println!("{}", &decryption);
            }
        }
    }
}

fn gen_G(q: BigInt) -> BigInt
{
    let lower = BigInt::from_u32(2).unwrap();
    let higher = q.clone() - BigInt::from_u32(1).unwrap();
    let mut g = RandBigInt::gen_bigint_range(&mut rand::thread_rng(), &lower.clone(), &higher.clone());
    loop
    {
        if is_primitive_root(g.clone(), &q.clone())
        {
            return g;
        }
        g = RandBigInt::gen_bigint_range(&mut rand::thread_rng(), &lower.clone(), &higher.clone());
    }
}

fn encrypt(message: String, q: BigInt, h: BigInt, k: BigInt) -> Vec<BigInt>
{
    let mut encryption: Vec<BigInt> = vec![];
    let mut preEncryption: Vec<char>  = vec![]; 
    let s = modexp_fast_internal_copy(h.clone(), k.clone(), q.clone());
    for i in 0..message.len()
    {
        preEncryption.push(message.chars().nth(i).unwrap());
    }
    for i in 0..preEncryption.len()
    {
        encryption.push(s.clone() * preEncryption[i] as u32);
    }
    return encryption
}

fn decrypt(encryption: Vec<BigInt>, p: BigInt, key: BigInt, q: BigInt) -> Vec<char>
{
    let mut decryption = Vec::<char>::new();
    let h = modexp_fast_internal_copy(p.clone(), key.clone(), q.clone());
    for i in 0..encryption.len()
    {
        let current_eq = (encryption[i].clone() / h.clone()).to_u32().unwrap();
        decryption.push(char::from_u32(current_eq).unwrap());
    }
    return decryption;
}

fn cyclicGroupCheck(q: BigInt, k: BigInt) -> BigInt //check that the large random fits within the cyclic group
{
    let big0 = BigInt::from_u64(0).unwrap();
    if q.clone() < k.clone()
    {
        return cyclicGroupCheck(k.clone(), q.clone());
    }
    else if q.clone() % k.clone() == big0
    {
        return k;
    }
    else
    {
        return cyclicGroupCheck(k.clone(), q.clone() % k.clone());
    }
}

fn keyGen(q: BigInt, g: BigInt) -> (BigInt, BigInt) //returns (privkey, pubkey)
{
    let big1 = BigInt::from_u64(1).unwrap();
    let lower_bound = big_pow(BigInt::from(10), BigInt::from(20));
    let mut key = RandBigInt::gen_bigint_range(
        &mut rand::thread_rng(), 
        &lower_bound,
        &q.clone()
    );
    let mut attempts = 0;
    let maxAttempts = 10000;
    while cyclicGroupCheck(q.clone(), key.clone()) != big1.clone()
    {
        if attempts < maxAttempts
        {
            key = RandBigInt::gen_bigint_range(
                &mut rand::thread_rng(),
                &lower_bound,
                &q.clone()
            ); 
            attempts = attempts + 1
        }
        else
        {
            println!("ElGamal KeyGen Exhausted Attempts, Killed to prevent front-end freezing");
            exit(1);
        }
    }
    assert!(key.clone() != q.clone()); 
    return (key.clone(), modexp_fast_internal_copy(g, key.clone(), q)) 
}

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

fn big_is_prime(n: &BigInt) -> bool //semi probabalistic miller-rabin primality test
{
    if n.is_even() {return false}; //this throws away 2 but it doesn't matter because it is for big integers
    
    let low_primes = vec![2, 3, 5, 7, 11, 13, 17, 19];
    for &prime in &low_primes
    {
        if n == &BigInt::from_u32(prime).unwrap()
        {
            return true;
        }
        if n.clone() % prime == BigInt::from_u32(0).unwrap()
        {
            return false;
        }
    }

    let mut d = n.clone() - BigInt::from_u32(1).unwrap();
    let mut s = 0;
    while d.is_even()
    {
        d /= 2;
        s += 1;
    }

    let bases = vec![
        BigInt::from(2),
        BigInt::from(325),
        BigInt::from(9375),
        BigInt::from(28178),
        BigInt::from(450775),
        BigInt::from(9780504),
        BigInt::from(1795265022),
    ];

    for base in bases
    {
        let mut x = modexp_fast_internal_copy(base, d.clone(), n.clone());
        if x == BigInt::from_u32(1).unwrap() || x == n - BigInt::from_u32(1).unwrap()
        {
            continue;
        }
        let mut i = 0;
        while i < s - 1 && x != n - BigInt::from_u32(1).unwrap()
        {
            x = modexp_fast_internal_copy(x, BigInt::from_u32(2).unwrap(), n.clone());
            i += 1;
        }
        if x != n - BigInt::from_u32(1).unwrap()
        {
            return false;
        }
    } 
    return true
}

pub fn pow_mod_Montgomery_Ladder(base: &BigInt, exp: &BigInt, m: &BigInt) -> BigInt //speedy sidechannel attack resistant modexp
{
    if !big_is_prime(m) { //implicitly checks for even value
        return BigInt::from_u32(1).unwrap();
    }
    let one = 1_u32.to_bigint().unwrap();
    let two = 2_u32.to_bigint().unwrap();
    let scaling_factor: BigInt = BigInt::from_u32(1 << (m.bits()  as usize + 1)).unwrap();
    let mut intermediateModVal = base.clone() * &scaling_factor % m;
    let mut intermediateProductVal = scaling_factor.clone();
    let mut exp_div = exp.clone();
    while exp_div > 0_u32.to_bigint().unwrap()
    {
        if exp_div.clone() % two.clone() == one.clone()
        {
            intermediateProductVal = &intermediateModVal * &intermediateProductVal % m;
            intermediateModVal = (&intermediateModVal - base * scaling_factor.clone()) % m;
        }
        else
        {
            intermediateModVal = (&intermediateModVal * &intermediateProductVal - &scaling_factor) % m;
            intermediateProductVal = &intermediateProductVal * &intermediateProductVal % m;
        }
        exp_div/= &two;
    }
    fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) 
    { //extended euclidean algorithm
        if a == &BigInt::from(0) {
            return (b.clone(), BigInt::from(0), BigInt::from(1));
        }

        let (gcd, x1, y1) = egcd(&(b % a), a);
        let x = y1 - ((b / a) * x1.clone());
        let y = x1;

        (gcd, x, y)
    }
    fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> //TODO: use this Some None return -> Option<SomeT> style more
    {
        let (gcd, x, _) = egcd(a, m);
        if gcd == BigInt::from_u32(1 ).unwrap()
        {
            Some((x % m + m) % m)
        } 
        else 
        {
            None
        }
    } 
    let mod_inverse = mod_inverse(&scaling_factor, &m).unwrap();
    (&intermediateModVal * &mod_inverse) % m
}


fn prime_factors(n: &BigInt) -> Vec<BigInt>
{
    let mut factors = Vec::new();
    let mut x: BigInt = n.clone();
    let limit = (BigInt::from(x.clone().sqrt()) + 1.to_bigint().unwrap()).to_usize();
    if let Some(limit) = limit {
        if limit < 2 {
            factors.push(x);
            return factors;
        }
        let sieve: Sieve = Sieve::new(limit);
        let primes = 
            sieve.primes_from(2)
            .take_while(|p| 
            {
                let bp = BigInt::from(*p);
                &bp * &bp <= x
            })
            .map(BigInt::from)
            .collect::<Vec<_>>();
        for p in primes 
        {
            while x.is_multiple_of(&p) 
            {
                factors.push(p.clone());
                x /= &p;
            }
        }
    } 
    else 
    {
        factors.push(x.clone());
    }
    if x > 1.to_bigint().unwrap() 
    {
        factors.push(x);
    }
    factors
}

pub fn is_primitive_root(g: BigInt, q: &BigInt) -> bool
{
    if !big_is_prime(q)
    {
        return  false;
    }
    let max = q - BigInt::from_u32(1).unwrap();
    let mut factors = prime_factors(&max);
    factors.sort();
    factors.dedup();
    for factor in factors.iter()
    {
        if factor == &BigInt::from_u32(2).unwrap()
        {
            continue
        }
        let res = modexp_fast_internal_copy(g.clone(), (&max / factor), q.clone());
        if res ==  BigInt::from_u32(1).unwrap()
        {
            return false
        }
    }
    true
}
