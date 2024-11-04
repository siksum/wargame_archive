#!/usr/bin/python3
#-*- coding:utf-8 -*- 

from flask import Flask, request, render_template_string
app=Flask(__name__)

with open('flag.txt', 'r') as f:
    flag = f.read()

app.secret_key=str(flag)
@app.route('/')
def home():
    title="This page is not secure. you can read flag in flag.txt"
    content = request.args.get('content')
    thisistemp='''
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="utf-8">
            <title>Simple Site: TryIngg~</title>
        </head>
        <body>  
            <h1>{{title}}</h1>
            <h2>%s</h2>
        </body>
    </html>'''%content
    return render_template_string(thisistemp, title=title)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5104)