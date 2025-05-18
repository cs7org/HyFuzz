import os
from modules.fuzz_tester.gan_model import (
    load_fuzz_data,
    train_gan,
    generate_test_cases
)


def main():
    # === Step 1: Load fuzz data from previous fuzzing logs ===
    log_path = "boofuzz-results/fuzz_output/fuzz.log"  # <-- Update if needed
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}")
        return

    print(f"[INFO] Loading fuzzing data from: {log_path}")
    fuzz_lengths = load_fuzz_data(log_path)

    if not fuzz_lengths:
        print("[WARNING] No valid fuzz cases found. Exiting.")
        return

    # === Step 2: Train GAN with fuzz data ===
    print(f"[INFO] Training GAN on {len(fuzz_lengths)} fuzz case(s)...")
    generator, _ = train_gan(fuzz_lengths, epochs=500, batch_size=16)

    # === Step 3: Generate new fuzz test cases ===
    print("[INFO] Generating new test cases using the trained GAN...")
    new_cases = generate_test_cases(generator, num_cases=10)

    # === Step 4: Output ===
    with open("boofuzz-results/fuzz_output/generated_cases.log", "w") as f:
        for case in new_cases:
            f.write(case + "\n")


if __name__ == "__main__":
    main()
