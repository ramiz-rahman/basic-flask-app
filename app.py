from flask import Flask
app = Flask(__name__)

# Routes and views
@app.route('/')
def index():
    return '<h1>Hello World!<h1>'

@app.route('/user/<name>')
def user(name):
    return '<h1>Hello %s!<h1>' % name

# Server startup
if __name__ == '__main__':
    app.run(debug=True)