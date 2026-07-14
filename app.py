from flask import Flask, render_template, request, jsonify

from detector import analyze_url
from threat_intel import check_threat_intel

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL"}), 400

    rule_result = analyze_url(url)
    intel_result = check_threat_intel(rule_result["url"])

    # If threat intel actively flags it, escalate verdict regardless of rule score.
    final_verdict = rule_result["verdict"]
    if intel_result["flagged"]:
        final_verdict = "dangerous"

    return jsonify({
        "url": rule_result["url"],
        "host": rule_result["host"],
        "risk_score": rule_result["risk_score"],
        "rule_based_verdict": rule_result["verdict"],
        "final_verdict": final_verdict,
        "reasons": rule_result["reasons"],
        "threat_intel": intel_result,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
