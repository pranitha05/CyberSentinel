import re

def check_password_strength(password):
    score = 0
    remarks = []

    if len(password) >= 8:
        score += 1
        remarks.append("✓ Good length")
    else:
        remarks.append("✗ Too short")

    if re.search(r'[A-Z]', password):
        score += 1
        remarks.append("✓ Has uppercase letter")
    else:
        remarks.append("✗ Missing uppercase letter")

    if re.search(r'[a-z]', password):
        score += 1
        remarks.append("✓ Has lowercase letter")
    else:
        remarks.append("✗ Missing lowercase letter")

    if re.search(r'\d', password):
        score += 1
        remarks.append("✓ Contains number")
    else:
        remarks.append("✗ Missing number")

    if re.search(r'[@$!%*?&#^()_+=-]', password):
        score += 1
        remarks.append("✓ Has special character")
    else:
        remarks.append("✗ Missing special character")

    strength_levels = {
        5: "Very Strong",
        4: "Strong",
        3: "Moderate",
        2: "Weak",
        1: "Very Weak",
        0: "Extremely Weak"
    }

    return {
        "score": score,
        "level": strength_levels.get(score, "Unknown"),
        "remarks": remarks
    }
