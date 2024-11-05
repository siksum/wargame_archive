import os
from flask import Flask, request, render_template
import re

app = Flask(__name__)

base_path = os.path.dirname(__file__)
flag_1_file_path = os.path.join(base_path, 'flag_1.txt')
flag_2_file_path = os.path.join(base_path, 'flag_2.txt')

try:
    with open(flag_1_file_path, "r") as f:
        FLAG_1 = f.read().strip()
except FileNotFoundError:
    FLAG_1 = "[**FLAG_1 NOT FOUND**]"

try:
    with open(flag_2_file_path, "r") as f:
        FLAG_2 = f.read().strip()
except FileNotFoundError:
    FLAG_2 = "[**FLAG_2 NOT FOUND**]"

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/blackhat", methods=["GET", "POST"])
def blackhat():
    flag_result_1 = None
    if request.method == "POST":
        input_val = request.form.get("input_val", "")
        m = re.match(r'b\d+l@\w{5,7}ck\.h@[a-z]{1,3}t', input_val)
        
        if m:
            flag_result_1 = FLAG_1
        else:
            flag_result_1 = '?'

    return render_template("blackhat.html", flag=flag_result_1)

@app.route("/whitehat", methods=["GET", "POST"])
def whitehat():
    flag_result_2 = None
    if request.method == "POST":
        input_val = request.form.get("input_val", "")
        m = re.match(r'wh[a-zA-Z0-9_]{5,7}it3[0-9]+\.h@[a-z]{4,6}t', input_val)
        
        if m:
            flag_result_2 = FLAG_2
        else:
            flag_result_2 = '?'

    return render_template("whitehat.html", flag=flag_result_2)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5107)
