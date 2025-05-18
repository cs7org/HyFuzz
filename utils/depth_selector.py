def select_max_depth():
    """
    Prompt the user to select a maximum fuzzing depth.
    Ensures the input is an integer between 1 and 5.

    Returns:
        int: The selected fuzzing depth (default is 3 if invalid input)
    """
    print("\n🧪 Select maximum fuzzing depth (1-5): ", end="")
    try:
        user_input = input().strip()
        depth = int(user_input)
        if 1 <= depth <= 5:
            return depth
        else:
            print("⚠️ Invalid input. Using default depth of 3.")
            return 3
    except Exception:
        print("⚠️ Invalid input. Using default depth of 3.")
        return 3
