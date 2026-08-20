#!/usr/bin/env python3
"""
Unit Test Suite for PRODIGY_CS_02: Image Encryptor
Author: Kaustubh Bangar
"""

import os
import unittest
import tempfile
import numpy as np
from PIL import Image
from image_encryptor import ImageEncryptor, process_image


class TestImageEncryptor(unittest.TestCase):

    def setUp(self):
        self.key = "TestSecretPasscode2026!"
        self.wrong_key = "WrongPasscode2026!"
        
        # Generate synthetic test images
        np.random.seed(42)
        self.rgb_array = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        self.rgba_array = np.random.randint(0, 256, (64, 64, 4), dtype=np.uint8)
        # Ensure alpha channel is opaque
        self.rgba_array[:, :, 3] = 255
        self.gray_array = np.random.randint(0, 256, (64, 64), dtype=np.uint8)

    def test_xor_rgb_roundtrip(self):
        encrypted = ImageEncryptor.encrypt_xor(self.rgb_array, self.key)
        self.assertFalse(np.array_equal(self.rgb_array, encrypted))
        
        decrypted = ImageEncryptor.decrypt_xor(encrypted, self.key)
        self.assertTrue(np.array_equal(self.rgb_array, decrypted))

    def test_swap_rgb_roundtrip(self):
        encrypted = ImageEncryptor.encrypt_swap(self.rgb_array, self.key)
        self.assertFalse(np.array_equal(self.rgb_array, encrypted))
        
        decrypted = ImageEncryptor.decrypt_swap(encrypted, self.key)
        self.assertTrue(np.array_equal(self.rgb_array, decrypted))

    def test_shuffle_rgb_roundtrip(self):
        encrypted = ImageEncryptor.encrypt_shuffle(self.rgb_array, self.key)
        self.assertFalse(np.array_equal(self.rgb_array, encrypted))
        
        decrypted = ImageEncryptor.decrypt_shuffle(encrypted, self.key)
        self.assertTrue(np.array_equal(self.rgb_array, decrypted))

    def test_combined_rgba_roundtrip(self):
        encrypted = ImageEncryptor.encrypt_combined(self.rgba_array, self.key)
        self.assertFalse(np.array_equal(self.rgba_array, encrypted))
        
        decrypted = ImageEncryptor.decrypt_combined(encrypted, self.key)
        self.assertTrue(np.array_equal(self.rgba_array, decrypted))

    def test_grayscale_roundtrip(self):
        encrypted = ImageEncryptor.encrypt_combined(self.gray_array, self.key)
        self.assertFalse(np.array_equal(self.gray_array, encrypted))
        
        decrypted = ImageEncryptor.decrypt_combined(encrypted, self.key)
        self.assertTrue(np.array_equal(self.gray_array, decrypted))

    def test_wrong_key_decryption(self):
        encrypted = ImageEncryptor.encrypt_combined(self.rgb_array, self.key)
        wrong_decrypted = ImageEncryptor.decrypt_combined(encrypted, self.wrong_key)
        self.assertFalse(np.array_equal(self.rgb_array, wrong_decrypted))

    def test_image_file_processing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            orig_path = os.path.join(tmp_dir, "original.png")
            enc_path = os.path.join(tmp_dir, "encrypted.png")
            dec_path = os.path.join(tmp_dir, "decrypted.png")
            
            # Save original PIL image
            img_orig = Image.fromarray(self.rgb_array)
            img_orig.save(orig_path)
            
            # Process Encrypt
            process_image(orig_path, enc_path, self.key, mode="combined", action="encrypt")
            self.assertTrue(os.path.exists(enc_path))
            
            # Process Decrypt
            process_image(enc_path, dec_path, self.key, mode="combined", action="decrypt")
            self.assertTrue(os.path.exists(dec_path))
            
            # Verify pixel identity
            with Image.open(dec_path) as img_dec:
                dec_array = np.array(img_dec)
            self.assertTrue(np.array_equal(self.rgb_array, dec_array))


if __name__ == '__main__':
    unittest.main()
