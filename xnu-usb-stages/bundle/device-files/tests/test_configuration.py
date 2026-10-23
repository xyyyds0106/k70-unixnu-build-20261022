#!/usr/bin/env python3
"""Reject the timer/provider mismatch found in Actions run 39614669422."""

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("source_build", ROOT / "tools/build_source_kernel.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {
            "XNU_SOURCE_CORECRYPTO14": True,
            "XNU_SOURCE_PTHREAD": True,
            "XNU_CRYPTO_BOOTSTRAP": "source",
            "XNU_NATIVE_ARCH_TIMER": False,
            "XNU_ARMCPU": False,
        }

    def test_source_build_without_interrupt_provider_is_accepted(self):
        BUILD.verify_configuration(self.baseline)

    def test_first_actions_configuration_is_rejected_early(self):
        self.baseline["XNU_NATIVE_ARCH_TIMER"] = True
        with self.assertRaisesRegex(ValueError, "XNU_NATIVE_ARCH_TIMER requires XNU_ARMCPU"):
            BUILD.verify_configuration(self.baseline)

    def test_source_build_cannot_enable_ufs(self):
        self.baseline["XNU_NATIVE_UFS"] = True
        with self.assertRaisesRegex(ValueError, "Unexpected feature.*XNU_NATIVE_UFS"):
            BUILD.verify_configuration(self.baseline)

    def test_platform_requires_all_interrupt_providers(self):
        with self.assertRaisesRegex(ValueError, "Platform profile requires"):
            BUILD.verify_configuration(self.baseline, "platform")
        self.baseline.update(XNU_ARM_DT_PLATFORM=True, XNU_ARMCPU=True, XNU_NATIVE_ARCH_TIMER=True, XNU_DT_PANIC_REGION=True)
        BUILD.verify_configuration(self.baseline, "platform")

    def test_platform_requires_dt_panic_region(self):
        self.baseline.update(XNU_ARM_DT_PLATFORM=True, XNU_ARMCPU=True, XNU_NATIVE_ARCH_TIMER=True)
        with self.assertRaisesRegex(ValueError, "Platform profile requires"):
            BUILD.verify_configuration(self.baseline, "platform")
        self.baseline["XNU_DT_PANIC_REGION"] = False
        with self.assertRaisesRegex(ValueError, "Platform profile requires"):
            BUILD.verify_configuration(self.baseline, "platform")

    def test_platform_profile_rejects_storage_and_board_power(self):
        self.baseline.update(XNU_ARM_DT_PLATFORM=True, XNU_ARMCPU=True, XNU_NATIVE_ARCH_TIMER=True, XNU_DT_PANIC_REGION=True)
        for feature in ("XNU_NATIVE_UFS", "XNU_OWNER_DATA_MOUNT", "XNU_SHENG_PMGR"):
            with self.subTest(feature=feature):
                invalid = dict(self.baseline, **{feature: True})
                with self.assertRaisesRegex(ValueError, "Unexpected feature"):
                    BUILD.verify_configuration(invalid, "platform")


if __name__ == "__main__":
    unittest.main()
