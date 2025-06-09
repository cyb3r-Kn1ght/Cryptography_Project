#!/usr/bin/env python3
import sys
import numpy as np
from pydub import AudioSegment
import matplotlib.pyplot as plt

def detect_watermark(path, block_ms=50, target_freq=19000, threshold_db=-50):
    # 1) Load audio và đưa về mono
    audio = AudioSegment.from_file(path)
    audio = audio.set_channels(1)
    sr = audio.frame_rate
    samples = np.array(audio.get_array_of_samples()).astype(np.float32)
    # normalize
    samples /= np.iinfo(audio.array_type).max

    # 2) Thiết lập
    block_size = int(sr * block_ms / 1000)
    n_blocks = len(samples) // block_size

    detected = []
    for i in range(n_blocks):
        block = samples[i*block_size:(i+1)*block_size]
        # window & FFT
        win = np.hanning(len(block))
        X = np.fft.rfft(block * win)
        freqs = np.fft.rfftfreq(len(block), 1/sr)
        mag_db = 20 * np.log10(np.abs(X) + 1e-6)

        # Tìm index gần target_freq nhất
        idx = np.argmin(np.abs(freqs - target_freq))
        if mag_db[idx] > threshold_db:
            detected.append((i, freqs[idx], mag_db[idx]))

    # 3) Kết quả
    if detected:
        print(f"Found watermark in {len(detected)}/{n_blocks} blocks:")
        for idx, f, db in detected:
            t = idx * block_ms / 1000
            print(f"  block {idx} @ {t:.3f}s → {f:.1f}Hz, {db:.1f} dB")
    else:
        print("No watermark detected (try lowering threshold_db)")

    # 4) Vẽ phổ block đầu tiên có watermark để minh hoạ
    if detected:
        idx0 = detected[0][0]
        block = samples[idx0*block_size:(idx0+1)*block_size]
        X = np.fft.rfft(block * np.hanning(len(block)))
        freqs = np.fft.rfftfreq(len(block), 1/sr)
        mag_db = 20 * np.log10(np.abs(X) + 1e-6)

        plt.figure(figsize=(8,4))
        plt.plot(freqs/1000, mag_db)
        plt.axvline(target_freq/1000, color='r', linestyle='--')
        plt.title(f"Spectrum of block {idx0} (~{idx0*block_ms/1000:.3f}s)")
        plt.xlabel("Frequency (kHz)")
        plt.ylabel("Magnitude (dB)")
        plt.xlim(0, sr/2000)
        plt.grid(True)
        plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_wm.py <audio_file>")
        sys.exit(1)
    detect_watermark(sys.argv[1])
