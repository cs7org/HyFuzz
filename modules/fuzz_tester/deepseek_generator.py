import os
import random


class DeepSeekGenerator:
    """
    Simulated DeepSeek model that 'learns' from fuzzing logs and generates fuzz test payloads.
    """
    def __init__(self, model_name="deepseek-r1:8b"):
        self.model_name = model_name
        self.learned_lengths = []
        print(f"[INFO] Using DeepSeek model: {self.model_name}")

    def _resolve_log_path(self, log_file=None):
        if log_file is not None:
            return log_file
        script_dir = os.path.abspath(os.path.dirname(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
        return os.path.join(project_root, "fuzz_output", "fuzz.log")

    def _resolve_output_path(self):
        script_dir = os.path.abspath(os.path.dirname(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
        output_dir = os.path.join(project_root, "generated_output")
        os.makedirs(output_dir, exist_ok=True)
        return os.path.join(output_dir, "generated_cases.log")

    def train_from_log(self, log_file=None):
        resolved_path = self._resolve_log_path(log_file)
        print(f"[INFO] Training DeepSeek model from: {resolved_path}")
        self.learned_lengths.clear()

        if not os.path.exists(resolved_path):
            print(f"[WARNING] Log file not found: {resolved_path}")
            return

        with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if "Transmitted" in line and "bytes:" in line:
                    try:
                        byte_str = line.split("bytes:")[-1].strip()
                        if byte_str.startswith("b'") or byte_str.startswith('b"'):
                            byte_data = eval(byte_str)
                            self.learned_lengths.append(len(byte_data))
                    except Exception as e:
                        print(f"[WARN] Skipping malformed line: {e}")
                        continue

        print(f"[INFO] Learned {len(self.learned_lengths)} fuzz case(s).")

    def generate(self, num_cases=10):
        print(f"[INFO] Generating {num_cases} test case(s) using DeepSeek...")
        if not self.learned_lengths:
            print("[WARNING] No training data found. Falling back to random lengths.")
            return [random.randint(5, 100) for _ in range(num_cases)]
        return [max(1, random.choice(self.learned_lengths) + random.randint(-2, 2)) for _ in range(num_cases)]

    def _build_fuzz_request(self, index, length):
        # Heuristic fuzzed path component using random printable characters
        payload = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=length))
        request = (
            f"[Generated case {index}] Length: {length}\n"
            f"GET /{payload} HTTP/1.1\r\n"
            f"Host: fuzzed.target.local\r\n"
            f"User-Agent: DeepSeek-Fuzzer\r\n"
            f"\r\n"
        )
        return request

    def save_generated_cases(self, num_cases=10):
        lengths = self.generate(num_cases)
        output_path = self._resolve_output_path()

        with open(output_path, "w", encoding="utf-8") as f:
            for i, length in enumerate(lengths):
                request = self._build_fuzz_request(i, length)
                print(request)
                f.write(request + "\n")

        print(f"[INFO] Output saved to: {output_path}")
        return output_path


if __name__ == "__main__":
    generator = DeepSeekGenerator()
    generator.train_from_log()
    generator.save_generated_cases(num_cases=1000)
