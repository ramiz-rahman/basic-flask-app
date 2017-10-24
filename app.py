from flask import Flask, render_template
app = Flask(__name__)

# Routes and views
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)

# Server startup
if __name__ == '__main__':
    app.run(debug=True)