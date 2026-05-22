# main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from zxcvbn import zxcvbn

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PasswordRequest(BaseModel):
    username: str
    password: str

def load_rules():
    with open("rules.json") as f:
        return json.load(f)

def validate_password(username, password, rules):
    results = {
        "length": len(password) >= rules.get("min_length", 12),
        "uppercase": any(c.isupper() for c in password) if rules.get("require_uppercase") else True,
        "lowercase": any(c.islower() for c in password) if rules.get("require_lowercase") else True,
        "digits": any(c.isdigit() for c in password) if rules.get("require_digits") else True,
        "specialChar": any(not c.isalnum() for c in password) if rules.get("require_special") else True,
        "noUsernameMatch": username.lower() not in password.lower() if rules.get("disallow_username_match") else True
    }
    return results

def get_strength_label(score):
    return ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"][score]

@app.post("/api/validate-password")
async def validate_pw(req: PasswordRequest):
    rules = load_rules()
    rule_results = validate_password(req.username, req.password, rules)
    suggestions = []

    if not rule_results["length"]:
        suggestions.append("Use at least {} characters".format(rules.get("min_length", 12)))
    if not rule_results["uppercase"]:
        suggestions.append("Include at least one uppercase letter")
    if not rule_results["lowercase"]:
        suggestions.append("Include at least one lowercase letter")
    if not rule_results["digits"]:
        suggestions.append("Include at least one digit")
    if not rule_results["specialChar"]:
        suggestions.append("Include at least one special character")
    if not rule_results["noUsernameMatch"]:
        suggestions.append("Avoid using your username in the password")

    if rules.get("use_zxcvbn", True):
        z_result = zxcvbn(req.password, user_inputs=[req.username])
        score = z_result["score"]
        suggestions.extend(z_result["feedback"]["suggestions"])
    else:
        score = sum(rule_results.values()) * 5 // len(rule_results)  # simplified fallback

    label = get_strength_label(score)

    return {
        "rules": rule_results,
        "zxcvbn_score": score,
        "suggestions": suggestions,
        "final_strength": label
    }
