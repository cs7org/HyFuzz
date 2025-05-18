def select_engine():
    """Prompt the user to choose a fuzzing engine."""
    print("\nSelect fuzzing engine:")
    print("1. BooFuzz")
    print("2. Hypothesis")
    while True:
        choice = input("Enter choice [1/2]: ").strip()
        if choice in ("1", "2"):
            return int(choice)
        print("Invalid input. Please enter 1 or 2.")


def select_generation():
    """
    Prompt the user to choose the test case generation strategy.

    Options:
    1. Use only raw fuzzing results
    2. Train and use GAN to generate test cases
    3. Train and use DeepSeek to generate test cases
    """
    print("\nSelect fuzz test case generation strategy:")
    print("1. Use only raw fuzzing results")
    print("2. Use GAN to generate new cases")
    print("3. Use DeepSeek to generate new cases")
    while True:
        choice = input("Enter choice [1/2/3]: ").strip()
        if choice in ("1", "2", "3"):
            return int(choice)
        print("Invalid input. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    fuzz_engine = select_engine()
    generation_strategy = select_generation()

    print(f"[INFO] Selected engine: {'BooFuzz' if fuzz_engine == 1 else 'Hypothesis'}")
    strategy_names = {
        1: "Raw output only",
        2: "GAN generation",
        3: "DeepSeek generation"
    }
    print(f"[INFO] Generation strategy: {strategy_names[generation_strategy]}")
