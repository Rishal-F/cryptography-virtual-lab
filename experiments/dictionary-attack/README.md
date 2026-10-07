# Dictionary Attack

## Aim

This experiment demonstrates a dictionary attack by testing predefined candidate passwords against a stored SHA-256 password hash.

## Objectives

- Understand the concept of a dictionary attack.
- Understand password hashing and SHA-256.
- Observe candidate password generation and iteration.
- Understand hash comparison and match detection.
- Observe successful and unsuccessful dictionary attacks.

## Theory

A dictionary attack is a password-guessing technique that tests passwords from a prepared list of likely candidates. The list may contain common passwords, words, and frequently used patterns.

Password hashes are one-way representations of passwords. Instead of storing a plaintext password, a system stores its hash. If an attacker obtains the stored hash, they can hash guessed passwords and compare the results with the target hash.

This simulation uses a predefined candidate dictionary. Each candidate password is processed using SHA-256, which produces a fixed-length hexadecimal digest. The candidate hash is compared with the stored target hash. If the values are equal, the candidate is identified as a match.

The attack stops immediately after a match because testing additional candidates is unnecessary once the target hash has been found. If every candidate has been tested without a match, the attack is unsuccessful for that dictionary. This means that the password was not found among the tested candidates, not necessarily that the password is secure.

## Algorithm

1. Read or generate the target password's stored SHA-256 hash.
2. Load the predefined candidate password dictionary.
3. Select the next candidate in dictionary order.
4. Generate the candidate's SHA-256 hash using the Web Crypto API.
5. Compare the candidate hash with the target hash.
6. If the hashes match, report the candidate and stop the attack.
7. If they do not match, record the attempt and continue with the next candidate.
8. If all candidates have been tested without a match, report that the password was not found.

## Simulation Features

- Target password input
- SHA-256 target hash generation
- Predefined candidate dictionary
- Step-by-step candidate testing
- Candidate hash display
- Hash comparison
- Attempt counter
- Progress indicator
- Success and failure result
- Reset control
- Quiz

## Test Cases

### 1. Common password

- **Target password:** `password`
- **Expected result:** Password Found
- **Expected attempts:** 3

### 2. First dictionary candidate

- **Target password:** `admin`
- **Expected result:** Password Found
- **Expected attempts:** 1

### 3. Password absent from dictionary

- **Target password:** `hello123`
- **Expected result:** Password Not Found
- **Expected attempts:** 5

## Technologies

- HTML5
- CSS3 using the repository's existing styles
- JavaScript
- Browser Web Crypto API
- SHA-256

## Files

- `index.html` — Experiment structure, theory, procedure, simulation UI, and quiz.
- `script.js` — SHA-256 hashing, dictionary attack engine, simulation logic, and quiz logic.
- `README.md` — Experiment documentation.

## How to Run

1. Open the repository locally in VS Code.
2. Start a local development server, such as the VS Code Live Server extension.
3. Open the repository's main page through the local server.
4. Select **Dictionary Attack** from the experiment browser, or open `experiments/dictionary-attack/index.html` through the server.
5. Use the Theory, Procedure, Simulation, and Quiz tabs to interact with the experiment.