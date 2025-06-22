from flask import Flask, render_template, request, session, redirect, url_for
import joblib
import os
from feature_extraction import extract_features, get_feature_names

app = Flask(__name__)
# A secret key is required to use sessions
app.secret_key = os.urandom(24)

# Load the Random Forest model
try:
    rf_model = joblib.load("model/rf_model.pkl")
except Exception as e:
    print(f"Error loading model: {e}")
    rf_model = None

@app.route("/")
def check():
    # The root is now the check page, it also displays history
    check_history = session.get("history", [])
    return render_template("check.html", history=check_history)

@app.route("/about")
def about():
    # Get feature names to display on the about page
    feature_names = get_feature_names()
    return render_template("about.html", feature_names=feature_names)

@app.route("/clear_history", methods=["POST"])
def clear_history():
    # Clear the history from the session
    session.pop("history", None)
    # Redirect back to the check page
    return redirect(url_for("check"))

@app.route("/predict", methods=["POST"])
def predict():
    if not rf_model:
        return render_template("check.html", error="Model is not loaded. Please check the server logs.")

    url = request.form.get("url")
    if not url:
        return render_template("check.html", error="Please provide a URL.")

    try:
        features = extract_features(url)
        if features is None or len(features) != 30:
            return render_template("check.html", error="Could not extract features from the URL.")

        prediction = rf_model.predict([features])[0]
        result_text = "Phishing" if prediction == 1 else "Legitimate"

        # Store result in session history
        if "history" not in session:
            session["history"] = []
        # Add the new result to the beginning of the list
        session["history"].insert(0, {"url": url, "result": result_text})
        session.modified = True # Ensure the session is saved

        reasoning = dict(zip(get_feature_names(), features))
        
        value_map = {-1: "Legitimate-like", 0: "Suspicious", 1: "Phishing-like"}
        reasoning_text = {k: value_map.get(v, "Unknown") for k, v in reasoning.items()}

        return render_template("result.html", 
                               result=result_text, 
                               url=url, 
                               reasoning=reasoning_text)

    except Exception as e:
        return render_template("check.html", error=f"An error occurred: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)
