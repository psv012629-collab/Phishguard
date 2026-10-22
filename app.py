from flask import Flask, render_template, request, redirect, url_for
from phishguard import analyze_url
import json
import os
from datetime import datetime

app = Flask(__name__)

HISTORY_FILE = "history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    history = load_history()

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            score, risk, reasons, recommendation = analyze_url(url)

            if risk == "HIGH RISK":
                css_class = "high"
            elif risk == "MEDIUM RISK":
                css_class = "medium"
            else:
                css_class = "safe"

            result = {
                "url": url,
                "score": score,
                "risk": risk,
                "reasons": reasons,
                "recommendation": recommendation,
                "css_class": css_class
            }

            history.insert(0, {
                "url": url,
                "score": score,
                "risk": risk,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            history = history[:50]
            save_history(history)

    return render_template(
        "index.html",
        result=result,
        history=history
    )


@app.route("/clear-history", methods=["POST"])
def clear_history():
    save_history([])
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
