from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def hello_world():
   print("Hello World")
   return request.args.get('text', '')

if __name__ == '__main__':
   app.run("0.0.0.0", "80")