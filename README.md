# HyFuzz: A Hybrid AI-Enhanced Vulnerability Detection Framework

**HyFuzz** is a modular two-stage vulnerability scanner that integrates deterministic CVE correlation with adaptive fuzz testing guided by machine learning. The system combines traditional signature-based methods with generative adversarial networks (GANs) and large language models (LLMs), enabling efficient detection of both known and previously undocumented vulnerabilities.

This repository provides the source code, evaluation scripts, and configuration files for the experiments presented in our IEEE RTSI 2025 submission.

---

## 📌 Overview

- **Stage 1:** CVE-based detection via banner fingerprinting and proof-of-concept (PoC) validation using Metasploit.
- **Stage 2:** Dynamic fuzzing with BooFuzz or Hypothesis, followed by optional payload corpus expansion using:
  - a fine-tuned GAN model, or
  - the zero-shot DeepSeek-r1 language model.
- **Output:** JSON and HTML reports including CVE hits, anomaly logs, and unique crash traces.

The architecture is protocol-agnostic and supports services such as HTTP, MQTT, Modbus, and CoAP.

---

## 📥 Installation

### Prerequisites
- Python 3.9+
- Docker (for PoC sandboxing)
- pip (Python package manager)

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/cs7org/HyFuzz.git
cd HyFuzz

# Install Python dependencies
pip install -r requirements.txt
```


## ▶️ Running the Scanner
Step 1: Basic Usage
```bash
python3 run_scan.py --targets 192.168.0.0/24 --fuzzer hypothesis --ai-mode deepseek
```

Step 2: Options
| Argument    | Description                    |
| ----------- | ------------------------------ |
| `--targets` | Target IP or CIDR range        |
| `--fuzzer`  | `boofuzz` or `hypothesis`      |
| `--ai-mode` | `none`, `gan`, or `deepseek`   |
| `--timeout` | Optional scan timeout per host |

Step 3: Results
Scan reports will be saved in:

- scan_report.json (machine-readable)
- report.html (human-readable)
- fuzz.log (trace of all fuzz attempts)

## 📊 Reproducing Results

To replicate the experiments described in the paper:

- Launch three local servers using test images: Apache 2.4, Nginx 1.18, and IIS 10.

- Run HyFuzz against each server in all four configurations:
  - CVE-only
  - Baseline fuzzing
  - Fuzz + GAN
  - Fuzz + DeepSeek

- Compare detection time, crash discovery, and false-positive rate as described in Section IV of the paper.

See experiments/configs/ for example scripts.

## 🧪 Configuration
Configuration files for fuzzers, models, and test environments are located in:
```bash
/configs/
├── targets.yaml
├── gan_config.json
├── deepseek_prompt.txt

Logs and outputs are written to /results by default.

```

## 📚 Citation
If you use HyFuzz in your research, please cite:
```bash
@misc{Hyfuzz,
  author       = {Yanlei Fu and Loui Al Sardy},
  title        = {HyFuzz: A Hybrid AI-Enhanced Vulnerability Detection Framework},
  howpublished = {\url{https://github.com/cs7org/HyFuzz}},
  year         = {2025},
  note         = {Accessed: 2025-05-14}
}
```

## 📄 License
HyFuzz is released under the MIT License. See LICENSE for full terms.

## 🤝 Contributing
We welcome contributions! Please open an issue or submit a pull request. For feature requests or collaboration inquiries, feel free to reach out.

## 📬 Contact
✉️ yanlei.fu@fau.de
✉️ loui.alsardy@fau.de
🌐 https://github.com/cs7org/HyFuzz

## 🔎 Acknowledgements
Developed as part of the CS7 Lab (Computer Networks and Communication Systems) at Friedrich–Alexander University Erlangen–Nürnberg (FAU).
