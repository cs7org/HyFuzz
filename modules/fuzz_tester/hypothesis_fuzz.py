import os
import string
import time
import requests
from datetime import datetime
from requests.exceptions import RequestException
from hypothesis import given, settings, strategies as st, Phase

ascii_chars = string.ascii_letters + string.digits + "-_:;.,/ "


def _resolve_log_path(output_dir=None, depth=1):
    """
    Resolve path for fuzz log output based on depth.
    """
    if output_dir:
        base_dir = output_dir
    else:
        script_dir = os.path.abspath(os.path.dirname(__file__))
        base_dir = os.path.abspath(os.path.join(script_dir, "..", "..", "fuzz_output"))

    os.makedirs(base_dir, exist_ok=True)
    return os.path.join(base_dir, f"fuzz2.log")


def run_hypothesis_fuzz(target_ip="localhost", port=80, num_examples=100, output_dir=None, depth=1):
    """
    Run Hypothesis-powered HTTP fuzzing against a target service.

    Args:
        target_ip (str): IP address of the target.
        port (int): HTTP port to test.
        num_examples (int): Base number of test cases (scales with depth).
        output_dir (str): Optional log output directory.
        depth (int): Fuzzing depth multiplier.

    Returns:
        str: Path to the generated fuzz log.
    """
    base_url = f"http://{target_ip}:{port}"
    total_cases = num_examples * depth
    test_case_counter = {"count": 0}
    log_path = _resolve_log_path(output_dir, depth=depth)

    def log_timestamp():
        return datetime.now().strftime("[%Y-%m-%d %H:%M:%S,%f]")[:-3]

    with open(log_path, "w", encoding="utf-8") as f:

        @settings(max_examples=total_cases, deadline=3000, phases=(Phase.generate,))
        @given(
            method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]),
            path=st.lists(
                st.text(min_size=1, max_size=5, alphabet=st.characters(whitelist_categories=('Ll', 'Lu', 'Nd'), whitelist_characters='-_')),
                min_size=1, max_size=3 + depth
            ).map(lambda segs: "/" + "/".join(segs)),
            query_params=st.dictionaries(
                st.text(min_size=1, max_size=5 + depth, alphabet=st.characters(whitelist_categories=('Ll', 'Lu', 'Nd'), whitelist_characters='-_')),
                st.text(min_size=0, max_size=8 + depth, alphabet=st.characters(whitelist_categories=('Ll', 'Lu', 'Nd'), whitelist_characters='-_')),
                min_size=0, max_size=3 + depth
            ),
            headers=st.dictionaries(
                st.text(min_size=1, max_size=12 + depth, alphabet=ascii_chars),
                st.text(min_size=0, max_size=20 + depth, alphabet=ascii_chars),
                min_size=0, max_size=3 + depth
            ),
            body=st.binary(min_size=0, max_size=100 + depth * 10)
        )
        def fuzz_case(method, path, query_params, headers, body):
            test_case_counter["count"] += 1
            case_id = test_case_counter["count"]
            url = base_url + path

            raw_preview = f"{method} {path} HTTP/1.1\r\nHost: {target_ip}\r\n"
            for k, v in headers.items():
                raw_preview += f"{k}: {v}\r\n"
            raw_preview += "\r\n"
            raw_bytes = raw_preview.encode("utf-8", errors="ignore") + body

            ts = log_timestamp()
            try:
                response = requests.request(method, url, params=query_params, headers=headers, data=body, timeout=2)
                status_code = response.status_code
                if status_code >= 500 or status_code < 100:
                    f.write(f"{ts}     Info: Sending fuzz case #{case_id}...\n")
                    f.write(f"{ts}     Transmitted {len(raw_bytes)} bytes: {raw_bytes!r}\n")
                    f.write(f"{ts}     [Anomaly] HTTP {status_code} {response.reason}\n")
                    f.write(f"{ts}     Info: Closing connection...\n")
                    f.write(f"{ts}     Info: Sleeping 0.2s...\n\n")
            except RequestException as e:
                f.write(f"{ts}     Info: Sending fuzz case #{case_id}...\n")
                f.write(f"{ts}     Transmitted {len(raw_bytes)} bytes: {raw_bytes!r}\n")
                f.write(f"{ts}     [Exception] {e}\n")
                f.write(f"{ts}     Info: Closing connection...\n")
                f.write(f"{ts}     Info: Sleeping 0.2s...\n\n")
            time.sleep(0.2)

        print(f"[Hypothesis] Fuzzing {base_url} with {total_cases} test cases (depth={depth})...\n")
        fuzz_case()

    print(f"\n[Hypothesis] Fuzzing complete. {test_case_counter['count']} cases tested.")
    print(f"[Hypothesis] Log saved to: {log_path}")
    return log_path


#  Local test entrypoint — main.py is responsible for orchestration in full runs
if __name__ == "__main__":
    run_hypothesis_fuzz("192.168.25.133", 80, num_examples=1000, depth=4)