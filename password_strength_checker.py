import re

def check_password_strength(password):
    score = 0

    # Length check
    if len(password) >= 8:
        score += 1
    # Uppercase check
    if re.search(r"[A-Z]", password):
        score += 1
    # Lowercase check
    if re.search(r"[a-z]", password):
        score += 1
    # Number check
    if re.search(r"[0-9]", password):
        score += 1
    # Special character check
    if re.search(r"[@$!%*?&]", password):
        score += 1

    # Strength evaluation
    if score <= 2:
        return "Weak 🔴"
    elif score == 3:
        return "Moderate 🟡"
    else:
        return "Strong 🟢"

if __name__ == "__main__":
    pwd = input("Enter a password: ")
    print("Password strength:", check_password_strength(pwd))
