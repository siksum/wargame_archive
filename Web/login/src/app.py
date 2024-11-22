from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_id = request.form.get('ID')
        user_pw = request.form.get('PW')

        if user_id == 'admin' and user_pw == 'babubabu':
            with open('flag.txt', 'r') as f:
                flag = f.read().strip()
            return f"플래그: {flag}"
        else:
            return render_template('index.html')

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5111)
