from flask import Flask, jsonify

app = Flask(__name__)

from config.logger import get_logger

logging = get_logger()


@app.route("/api/endpoint")
def api_endpoint():
    return jsonify({"message": "API endpoint reached successfully"})


# Run the application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
