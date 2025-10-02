#!/usr/bin/env python3
"""
password_checker.py
Simple password strength checker (entropy + wordlist check).

"""

import argparse
import getpass
import math
import string
from pathlib import Path

def charset_size(pw: str) -> int:
    size = 0
    if any(c.islower() for c in pw): size += 26
    if any(c.isupper() for c in pw): size += 26
    if any(c.isdigit() for c in pw): size += 10
    if any(c in string.punctuation for c in pw): size += len(string.punctuation)
    if any(ord(c) > 127 for c in pw): size += 100   # rough extra for unicode chars
    return size

def calculate_entropy(pw: str) -> float:
    R = charset_size(pw)
    L = len(pw)
    return round(L * math.log2(R), 2) if R > 0 and L > 0 else 0.0

def load_wordlist(path: Path) -> set:
    if not path.exists(): 
        return set()
    with path.open("r", encoding="latin-1", errors="ignore") as f:
        return {line.strip() for line in f if line.strip()}

def in_wordlist(pw: str, wordset: set) -> bool:
    return pw in wordset

def evaluate(pw: str, wordset: set):
    entropy = calculate_entropy(pw)
    compromised = in_wordlist(pw, wordset)
    if compromised or entropy < 40:
        rating = "Weak"
    elif 40 <= entropy <= 60:
        rating = "Medium"
    else:
        rating = "Strong"

    suggestions = []
    if compromised:
        suggestions.append("This password appears in common password lists — change it immediately.")
    if len(pw) < 12:
        suggestions.append("Increase length to at least 12 characters.")
    if not any(c.islower() for c in pw):
        suggestions.append("Add lowercase letters.")
    if not any(c.isupper() for c in pw):
        suggestions.append("Add uppercase letters.")
    if not any(c.isdigit() for c in pw):
        suggestions.append("Add digits.")
    if not any(c in string.punctuation for c in pw):
        suggestions.append("Add symbols (e.g., !@#).")

    return {
        "length": len(pw),
        "entropy": entropy,
        "rating": rating,
        "compromised": compromised,
        "suggestions": suggestions
    }

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("-w", "--wordlist", default="common_passwords.txt",
                        help="path to wordlist (one password per line)")
    parser.add_argument("--show-entropy", action="store_true",
                        help="display entropy value")
    args = parser.parse_args()

    wordset = load_wordlist(Path(args.wordlist))
    pw = getpass.getpass("Enter password (hidden): ")

    result = evaluate(pw, wordset)

    print("\n--- Password Check ---")
    print(f"Length: {result['length']}")
    if args.show_entropy:
        print(f"Entropy: {result['entropy']} bits")
    print(f"Rating: {result['rating']}" + (" (found in wordlist)" if result['compromised'] else ""))
    if result['suggestions']:
        print("\nSuggestions:")
        for s in result['suggestions']:
            print(" -", s)

if __name__ == "__main__":
    main()
