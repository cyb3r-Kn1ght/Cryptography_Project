from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

@app.route('/')
def index():
    music_dir = os.path.join(app.root_path, 'static', 'music')
    music_files = os.listdir(music_dir)
    return render_template("index.html", music_files=music_files)

@app.route('/music/<filename>')
def play_music(filename):
    return send_from_directory("static/music", filename)

if __name__ == '__main__':
    app.run()
