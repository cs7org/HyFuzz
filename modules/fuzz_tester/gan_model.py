import os
import random
import tensorflow as tf
from datetime import datetime


def _resolve_log_path(log_file=None):
    if log_file:
        return log_file
    script_dir = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    return os.path.join(project_root, "fuzz_output", "fuzz.log")


def _resolve_output_path():
    script_dir = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    output_dir = os.path.join(project_root, "generated_output")
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, "generated_cases.log")


def load_fuzz_data(log_file=None):
    resolved_path = _resolve_log_path(log_file)
    test_cases = []

    try:
        with open(resolved_path, 'r', errors='ignore') as f:
            session = []
            include = False
            for line in f:
                if "Info: Sending fuzz case" in line:
                    session = [line]
                    include = False
                elif "Transmitted" in line:
                    session.append(line)
                elif "[Exception]" in line or "[Anomaly]" in line:
                    session.append(line)
                    include = True
                elif "Closing connection" in line or "Sleeping" in line:
                    session.append(line)
                    if include:
                        for l in session:
                            if "Transmitted" in l and "bytes:" in l:
                                try:
                                    raw = l.split("bytes:")[-1].strip()
                                    if raw.startswith("b'") or raw.startswith('b"'):
                                        byte_str = eval(raw)
                                        test_cases.append(len(byte_str))
                                except Exception as e:
                                    print(f"[WARN] Failed to parse transmitted line: {e}")
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {resolved_path}")
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {e}")

    print(f"[INFO] Total fuzz cases loaded: {len(test_cases)}")
    return test_cases


def build_generator():
    model = tf.keras.Sequential(name="generator")
    model.add(tf.keras.Input(shape=(100,)))
    model.add(tf.keras.layers.Dense(64, activation='relu'))
    model.add(tf.keras.layers.Dense(32, activation='relu'))
    model.add(tf.keras.layers.Dense(1, activation='linear'))
    return model


def build_discriminator():
    model = tf.keras.Sequential(name="discriminator")
    model.add(tf.keras.Input(shape=(1,)))
    model.add(tf.keras.layers.Dense(32, activation='relu'))
    model.add(tf.keras.layers.Dense(16, activation='relu'))
    model.add(tf.keras.layers.Dense(1, activation='sigmoid'))
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.0002),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    return model


def train_gan(data, epochs=500, batch_size=32):
    if not data:
        print("[WARNING] No training data provided. Using fallback data.")
        data = [10, 20, 30, 40, 50]

    data_tensor = tf.convert_to_tensor(data, dtype=tf.float32)
    dataset = tf.data.Dataset.from_tensor_slices(data_tensor).shuffle(buffer_size=len(data)).batch(batch_size)

    generator = build_generator()
    discriminator = build_discriminator()

    discriminator.trainable = False
    gan_input = tf.keras.Input(shape=(100,))
    gan_output = discriminator(generator(gan_input))
    gan_model = tf.keras.Model(inputs=gan_input, outputs=gan_output)
    gan_model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.0002),
        loss='binary_crossentropy'
    )

    for epoch in range(epochs):
        d_loss_total = 0.0
        g_loss_total = 0.0
        for real_batch in dataset:
            batch_size = real_batch.shape[0]

            noise = tf.random.normal((batch_size, 100))
            fake_batch = generator.predict(noise, verbose=0)

            real_labels = tf.ones((batch_size, 1))
            fake_labels = tf.zeros((batch_size, 1))

            discriminator.trainable = True
            d_loss_real = discriminator.train_on_batch(tf.reshape(real_batch, (-1, 1)), real_labels)
            d_loss_fake = discriminator.train_on_batch(fake_batch, fake_labels)
            d_loss = 0.5 * (d_loss_real[0] + d_loss_fake[0])
            d_loss_total += d_loss

            noise = tf.random.normal((batch_size, 100))
            discriminator.trainable = False
            g_loss = gan_model.train_on_batch(noise, tf.ones((batch_size, 1)))
            g_loss_total += g_loss

        if (epoch + 1) % max(1, epochs // 10) == 0 or epoch == 0:
            print(f"[Epoch {epoch+1}/{epochs}] D Loss: {d_loss_total:.4f} | G Loss: {g_loss_total:.4f}")

    return generator, discriminator


def generate_test_cases(generator, num_cases=10):
    if generator is None:
        return []

    output_path = _resolve_output_path()
    noise = tf.random.normal((num_cases, 100))
    generated = generator.predict(noise, verbose=0)

    with open(output_path, "w", encoding="utf-8") as f:
        for i, val in enumerate(generated):
            length = max(1, int(val[0]))
            payload = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=length))
            request = f"GET /{payload} HTTP/1.1\r\nHost: fuzzed.target.local\r\nUser-Agent: GAN-Fuzzer\r\n\r\n"
            raw_bytes = request.encode("utf-8", errors="ignore")
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S,%f]")[:-3]

            f.write(f"{timestamp}     Info: Sending generated case #{i}...\n")
            f.write(f"{timestamp}     Transmitted {len(raw_bytes)} bytes: {raw_bytes!r}\n")
            f.write(f"{timestamp}     Info: Closing connection...\n")
            f.write(f"{timestamp}     Info: Sleeping 0.2s...\n\n")

            print(f"{timestamp}     Info: Sending generated case #{i}...")
            print(f"{timestamp}     Transmitted {len(raw_bytes)} bytes: {raw_bytes!r}")
            print(f"{timestamp}     Info: Closing connection...")
            print(f"{timestamp}     Info: Sleeping 0.2s...\n")

    print(f"[INFO] Output saved to: {output_path}")
    return output_path


if __name__ == "__main__":
    data = load_fuzz_data()
    generator, _ = train_gan(data, epochs=500)
    generate_test_cases(generator, num_cases=100)
