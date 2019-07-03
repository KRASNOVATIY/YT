import os
import unittest
from unittest.mock import patch

from apk_analyze import APKInfo
from tests import PATH_WITH_APK


class Tester(unittest.TestCase):

    @patch("apk_analyze.APKOpener", autospec=True)  # we want not extract data from apk
    def test_all_without_opener(self, opener):
        opener.return_value = None
        for file in os.listdir(PATH_WITH_APK):
            file_path = os.path.join(PATH_WITH_APK, file)
            apk_info = APKInfo(file_path)
            self.assertIsNone(apk_info.apk_opener)
            self.assertIsInstance(apk_info.name, (str, type(None)))
            self.assertIsInstance(apk_info.is_use_dcl(), bool)
            [self.assertRegex(code, "^[*#][\d*#]*\d[\d*#]*$") for code in apk_info.get_codes()]

    def test_crackhouse(self):
        apk_info = APKInfo(os.path.join(PATH_WITH_APK, "crackhouse.apk"))
        self.assertIsNone(apk_info.name)
        self.assertFalse(apk_info.is_use_dcl())
        self.assertIs(len(apk_info.get_codes()), 0)

        self.assertDictEqual(
            apk_info.get_flags(),
            {'allowBackup': 'true', 'supportsRtl': 'true', 'android.webkit.WebView.MetricsOptOut': 'false'}
        )

        self.assertListEqual(
            apk_info.get_libraries_manifest(),
            list()
        )
        self.assertListEqual(
            apk_info.get_libraries_packages(),
            ['android.support.annotation', 'android.support.compat', 'android.support.coreui',
             'android.support.coreutils', 'android.support.fragment', 'android.support.graphics',
             'android.support.mediacompat', 'android.support.v4', 'android.support.v7', 'com.crack.stocker']
        )
        self.assertSetEqual(
            apk_info.get_dll_libraries(),
            set()
        )
        self.assertSetEqual(
            apk_info.get_native_libraries(),
            {'libm.so', 'libstdc++.so', 'libc.so', 'liblog.so', 'libdl.so', 'libnative-lib.so'}
        )


if __name__ == "__main__":
    unittest.main()