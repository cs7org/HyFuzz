from boofuzz import *
import os
import datetime
from multiprocessing import Process


class CustomLogger(FuzzLogger):
    def __init__(self, file_handle):
        super().__init__()
        self.file_handle = file_handle

    def log_check_fail(self, message):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S,%f]")[:-3]
        crash_msg = f"{timestamp}     [CRASH] {message}"
        print(crash_msg)
        self.file_handle.write(crash_msg + "\n")
        self.file_handle.flush()

    def log_fail(self, message):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S,%f]")[:-3]
        fail_msg = f"{timestamp}     [FAIL] {message}"
        print(fail_msg)
        self.file_handle.write(fail_msg + "\n")
        self.file_handle.flush()

    def log_send(self, data):
        print(f"[SEND] {data!r}")

    def log_recv(self, data):
        print(f"[RECV] {data!r}")

    def log_info(self, message=None, **kwargs):
        if message:
            print(f"[INFO] {message}")

    def log_warn(self, message=None, **kwargs):
        if message:
            print(f"[WARN] {message}")

    def log_error(self, message=None, **kwargs):
        if message:
            print(f"[ERROR] {message}")


def create_http_request(method, depth, target_ip):
    s_initialize(f"HTTP {method}")
    if s_block_start(f"request-{method}"):
        s_string(method)
        s_delim(" ")
        s_string("/index.html")
        s_delim(" ")
        s_string("HTTP/1.1")
        s_static("\r\n")
        s_string(f"Host: {target_ip}")
        s_static("\r\n")

        for i in range(depth):
            s_string(f"X-Fuzz-{i}")
            s_delim(": ")
            s_string("A" * (8 * (i + 1)))
            s_static("\r\n")

        s_string("User-Agent")
        s_delim(": ")
        s_string("Mozilla/5.0")
        s_static("\r\n")

        s_string("Accept")
        s_delim(": ")
        s_string("*/*")
        s_static("\r\n")

        if method in ["POST", "PUT", "PATCH"]:
            s_string("Content-Type")
            s_delim(": ")
            s_string("application/x-www-form-urlencoded")
            s_static("\r\n")
            s_string("Content-Length")
            s_delim(": ")
            s_string("13")
            s_static("\r\n")

        s_string("Connection")
        s_delim(": ")
        s_string("close")
        s_static("\r\n\r\n")

        if method in ["POST", "PUT", "PATCH"]:
            s_string("param=value")
    s_block_end()


def run_method_fuzz(method, target_ip, port, depth, log_file_path):
    with open(log_file_path, "a", encoding="utf-8") as log_file_handle:
        print(f"[*] Starting fuzzing for method: {method}")
        session = Session(
            target=Target(connection=TCPSocketConnection(target_ip, port)),
            sleep_time=0.1,
            check_data_received_each_request=True,
            fuzz_loggers=[CustomLogger(file_handle=log_file_handle)],
            web_port=None
        )

        create_http_request(method, depth, target_ip)
        session.connect(s_get(f"HTTP {method}"))
        session.fuzz(max_depth=depth)
        print(f"[+] Finished fuzzing for method: {method}")


def run_boofuzz(target_ip, port, depth=1, output_dir=None):
    if output_dir is None:
        script_dir = os.path.abspath(os.path.dirname(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
        output_dir = os.path.join(project_root, "fuzz_output")

    os.makedirs(output_dir, exist_ok=True)

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
    processes = []

    for method in methods:
        log_path = os.path.join(output_dir, "fuzz.log")
        p = Process(target=run_method_fuzz, args=(method, target_ip, port, depth, log_path))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    print("[+] All fuzzing processes completed.")
    return output_dir


if __name__ == "__main__":
    target_ip = "192.168.25.133"
    port = 80
    depth = 2
    run_boofuzz(target_ip, port, depth)
