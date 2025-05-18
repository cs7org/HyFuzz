import requests
import time
import json
import os
import re


def extract_payloads_from_log(filepath):
    """
    提取带有 Transmitted 的 HTTP 请求 payload。
    """
    payloads = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if "Transmitted" in line and "bytes:" in line:
                match = re.search(r"bytes:\s+(b[\"'].*[\"'])", line)
                if match:
                    try:
                        raw_bytes = eval(match.group(1))
                        if isinstance(raw_bytes, bytes):
                            decoded = raw_bytes.decode("utf-8", errors="ignore")
                            payloads.append(decoded)
                    except Exception as e:
                        print(f"[WARN] Failed to decode line: {e}")
    return payloads


def test_generated_cases(ip, port, filepath, logger):
    url = f"http://{ip}:{port}"
    payloads = extract_payloads_from_log(filepath)
    results = []

    logger.info(f"Starting generalization test with {len(payloads)} payloads from log {filepath} on {url}...")

    for i, payload in enumerate(payloads):
        try:
            start_time = time.time()
            response = requests.get(url, data=payload, timeout=3)
            duration = round(time.time() - start_time, 3)

            result = {
                "index": i,
                "payload": payload,
                "status_code": response.status_code,
                "response_time": duration,
                "suspicious": response.status_code >= 500
            }

        except Exception as e:
            result = {
                "index": i,
                "payload": payload,
                "status_code": "ERROR",
                "error": str(e),
                "suspicious": True
            }

        results.append(result)

    suspicious_count = sum(r["suspicious"] for r in results)
    logger.info(f"Generalization test completed. {suspicious_count} suspicious responses detected out of {len(results)}.")
    return results


def main():
    from utils.logger import setup_logger
    logger = setup_logger()

    ip = "192.168.25.133"
    port = 80

    base_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_dir, "..", "..", "generated_output", "generated_cases.log")
    filepath = os.path.abspath(filepath)

    if not os.path.exists(filepath):
        logger.error(f"Test case file not found: {filepath}")
        return

    results = test_generated_cases(ip, port, filepath, logger)

    output_path = os.path.join(os.path.dirname(filepath), "generalization_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_path}")

    logger.info("Showing preview of results:")
    for entry in results[:5]:
        logger.info(json.dumps(entry, indent=2))


if __name__ == "__main__":
    main()
