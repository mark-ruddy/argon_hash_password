# Argon Hash Password
Functions for creating hashed passwords with salt using argon2

### Create a hashed password with salt

```
let (hash, salt) = argon_hash_password::create_hash_and_salt("PlaintextPassword");
```

The hash and salt can then be stored

### Check a Hash

```
let check = argon_hash_password::check_password_matches("PlaintextPassword", hash, salt);

match check {
  true => println!("Correct plaintext password provided"),
  false => println!("Incorrect plaintext password provided"),
}
```
