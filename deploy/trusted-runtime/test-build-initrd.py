import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-initrd.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class InitrdContract(unittest.TestCase):
    def test_static_elf_validation_and_deterministic_archive(self):
        raw = bytearray(120)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", raw, 18, 62)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<I", raw, 64, 1)
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "fixture.elf"
            template = Path(directory) / "template"
            elf.write_bytes(raw)
            template.write_text("chatml")
            first, profile = builder.build(elf, elf, template, "a" * 64, "b" * 64, 1000)
            self.assertEqual(first, builder.build(elf, elf, template, "a" * 64, "b" * 64, 1000)[0])
            self.assertIn(b"etc/hypermesh-meter/profile.json\0", first)
            self.assertEqual(profile["model_sha256"], profile["tokenizer_sha256"])
            self.assertNotIn(b"private_key", first)
            struct.pack_into("<I", raw, 64, 3)
            elf.write_bytes(raw)
            with self.assertRaises(ValueError):
                builder.static_elf(elf)


if __name__ == "__main__":
    unittest.main()
