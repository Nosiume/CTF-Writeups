from flask import Flask, render_template, request, jsonify, make_response, send_from_directory
from pwn import *
import time
import threading
import secrets


app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BINARY_PATH = "./canvas_manager"
RESET_INTERVAL = 70 # reset interval in seconds

binary_process = None
process_lock = threading.Lock()
global_messages = []
messages_lock = threading.Lock()

def start_binary():
    global binary_process
    if binary_process:
        binary_process.close()
    binary_process = process(BINARY_PATH)
    binary_process.recvline()

def send_command(command):
    global binary_process
    
    if '-' in str(command):
        return "Hehehe nice try..."
    
    with process_lock:
        if not binary_process:
            start_binary()
        try:
            binary_process.sendline(command.encode())
            response = ""
            if command.startswith("GET ") and not command.startswith("GETALL"):
                line1 = binary_process.recvline().decode().strip()
                response = line1
                if line1.startswith("GET"):
                    response += "\n" + binary_process.recvline().decode().strip()
            elif command == "GETALL":
                first_line = binary_process.recvline().decode().strip()
                response = first_line
                if first_line.startswith("CANVASES"):
                    for _ in range(int(first_line.split()[1])):
                        response += "\n" + binary_process.recvline().decode().strip()
            else:
                response = binary_process.recvline().decode().strip()
            return response
        except Exception as e:
            try:
                if binary_process:
                    binary_process.close()
            except:
                pass
            binary_process = None
            return "ERROR"


def reset_memory():
    while True:
        time.sleep(RESET_INTERVAL)
        with process_lock:
            start_binary()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/canvas')
def admin_canvas():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return "Access denied. Admin access required.", 403
    return render_template('admin_canvas.html')

# XSS in BOT panel so we can make it call potentially vulnerable functions as ADMIN
@app.route('/admin/messages')
def admin_messages():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return "Access denied. Admin access required.", 403
    with messages_lock:
        messages = list(global_messages)
    resp = make_response(render_template('admin_messages.html', messages=messages))
    delete_messages()
    return resp

@app.route('/api/canvas/create', methods=['POST'])
def api_create_canvas():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    data = request.json
    canvas_id = data.get('id', 1)
    try:
        width = int(data.get('width', 10)) # default
        height = int(data.get('height', 10)) # default
    except:
        return jsonify({'status': 'error', 'message': 'Invalid width or height'}), 400
    if width > 50 or height > 50:
        return jsonify({'status': 'error', 'message': 'Max size is 50x50'}), 400
    response = send_command(f"CREATE {canvas_id} {width} {height}")
    if response.startswith("OK"):
        return jsonify({'status': 'success', 'id': canvas_id})
    return jsonify({'status': 'error', 'message': response}), 400

@app.route('/api/canvas/set', methods=['POST'])
def api_set_pixel():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    data = request.json
    color = data.get('color', '0x000000')
    if color.startswith('#'):
        color = '0x' + color[1:]
    response = send_command(f"SET {data.get('id')} {data.get('x')} {data.get('y')} {color}")
    if response == "OK":
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': response}), 400

@app.route('/api/canvas/get/<int:canvas_id>', methods=['GET'])
def api_get_canvas(canvas_id):
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    response = send_command(f"GET {canvas_id}")
    if response.startswith("ERROR"):
        return jsonify({'status': 'error', 'message': 'Canvas not found'}), 404
    lines = response.split('\n')
    if len(lines) >= 2:
        pixels = lines[1].strip('()').split(',')
        return jsonify({'status': 'success', 'id': canvas_id, 'pixels': pixels})
    return jsonify({'status': 'error'}), 400

@app.route('/api/canvas/list', methods=['GET'])
def api_list_canvas():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    response = send_command("GETALL")
    canvases = []
    lines = response.split('\n')
    if lines[0].startswith("CANVASES"):
        for line in lines[1:]:
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    canvases.append({'id': int(parts[0]), 'dimensions': parts[1]})
    return jsonify({'status': 'success', 'canvases': canvases})

@app.route('/api/canvas/delete/<int:canvas_id>', methods=['DELETE'])
def api_delete_canvas(canvas_id):
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    response = send_command(f"DELETE {canvas_id}")
    if response.startswith("OK"):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': response}), 400

def delete_messages():
    with messages_lock:
        count = len(global_messages)
        global_messages.clear()

@app.route('/api/canvas/exit', methods=['POST'])
def api_exit_binary():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
    global binary_process
    with process_lock:
        try:
            if binary_process:
                binary_process.sendline("EXIT".encode())
                binary_process = None
                start_binary()
                return jsonify({'status': 'success', 'message': 'Binary exited and restarted'})
            return jsonify({'status': 'error', 'message': 'No binary process running'}), 400
        except Exception as e:
            try:
                if binary_process:
                    binary_process.close()
            except:
                pass
            binary_process = None
            start_binary()
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/message', methods=['POST'])
def api_send_message():
    data = request.json
    with messages_lock:
        global_messages.append({
            'author': data.get('author', 'Anonymous'),
            'content': data.get('content', ''),
            'timestamp': time.time()
        })
    return jsonify({'status': 'success'})


if __name__ == '__main__':
    start_binary()
    threading.Thread(target=reset_memory, daemon=True).start()
    app.run(host='0.0.0.0', port=5080)
