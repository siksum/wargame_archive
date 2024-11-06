from flask import Flask, request, render_template

app = Flask(__name__)

app.config['DEBUG'] = False

is_imported = False

@app.route('/')
def index():
    return '''
        <html>
            <head><title>I Love Corn</title></head>
            <body>
                <h1>I Love Corn</h1>
                <img src="/static/corn.jpg" alt="옥수수" style="max-width:100%; height:auto;">
            </body>
        </html>
    '''

@app.route('/console')
def console():
    return render_template('console.html')

@app.route('/execute', methods=['POST'])
def execute():
    global is_imported
    command = request.form.get('command')

    if command == 'import os':
        is_imported = True
        return ""

    if command.startswith("os.popen("):
        if not is_imported:
            return "Import 'os' first!"

    if command == 'os.popen(\'ls\').read()':
        return "app.py\nflag.txt\n"
    elif command == 'os.popen(\'cat ./flag.txt\').read()':
        with open('flag.txt', 'r') as f:
            return f.read()
    elif command == 'os.popen(\'cat ./app.py\').read()':
        with open('app.py', 'r') as f:
            return f.read()

    return "Invalid command"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5108)