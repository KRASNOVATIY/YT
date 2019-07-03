# python 3.6

import os
import re
import sys
import glob
import shutil
import zipfile
from collections import OrderedDict
from typing import List, Dict, Set

import apkutils
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError


class APKOpener(object):

    def __init__(self, path_to_apk: str):
        """
        Инициализируем сущность, раскрываем архив apk
        :param path_to_apk: (str) путь к .apk
        """
        self.path = path_to_apk
        self.current_path = os.getcwd()
        self.tmp = os.path.join(os.path.dirname(self.path), f".{os.path.basename(self.path)}")
        zf = zipfile.ZipFile(self.path)
        zf.extractall(self.tmp)

    def __del__(self):
        """
        Удаляем временную папку
        :return:
        """
        shutil.rmtree(self.tmp)

    def use_path(method):
        """
        Декоратор, позволяющий исполнять методы в директории self.tmp
        (у меня редакторы PCProf и VSCode ругаются на `method` и `@use_path`, не понимают, что работают с декоратором)
        :return:
        """
        def wrapper(self):
            os.chdir(self.tmp)
            result = method(self)
            os.chdir(self.current_path)
            return result
        return wrapper

    @use_path
    def get_native_libs(self) -> Set[str]:
        """
        Получаем множество всех нативных библиотек в пакете .apk
        :return: (set) библиотеки
        """
        native_libs = set()
        so_files = dict()

        for lib_path in self._get_files_by_pattern("**/*.so"):
            lib = os.path.basename(lib_path)
            if lib not in so_files:
                so_files[lib] = lib_path
        for file in so_files.values():
            native_libs.update(self._get_libs_from_so(file))

        return native_libs

    @use_path
    def get_dll_libs(self) -> Set[str]:
        """
        Получаем множество всех библиотек dll (NET) в пакете .apk
        :return: (set) библиотеки
        """
        return set([os.path.basename(lib) for lib in self._get_files_by_pattern("*/**.dll")])

    @staticmethod
    def _get_files_by_pattern(pattern: str) -> List[str]:
        """
        Находим в .apk файлы, соответствующие паттерну
        :param pattern: (str) паттерн
        :return: (list)
        """
        return glob.glob(pattern, recursive=True)

    @staticmethod
    def _get_libs_from_so(file_path: str) -> List[str]:
        """
        Получаем список нативных библиотек из файла .so
        :param file_path: (str) путь к файлу
        :return: (list) спиок нативных библиотек
        """
        native_libraries = list()

        if not file_path.endswith(".so"):
            raise RuntimeError("File extension not match \'.so\'")

        with open(file_path, "rb") as file:
            try:
                elffile = ELFFile(file)
            except ELFError:
                return native_libraries
            else:
                for section in elffile.iter_sections():
                    if not isinstance(section, DynamicSection):
                        continue
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            native_libraries.append(tag.needed)
                        elif tag.entry.d_tag == 'DT_RPATH':
                            native_libraries.append(tag.rpath)
                        elif tag.entry.d_tag == 'DT_RUNPATH':
                            native_libraries.append(tag.runpath)
                        elif tag.entry.d_tag == 'DT_SONAME':
                            native_libraries.append(tag.soname)

        return native_libraries


class APKInfo(object):
    def __init__(self, path_to_apk: str):
        """
        Инициализируем сущность
        :param path_to_apk: (str) путь к .apk
        """
        self._apk = apkutils.APK(path_to_apk)
        self._manifest = self._apk.get_manifest()
        if not self._manifest:
            raise RuntimeError("Could not recognize file as Android APK")
        self.apk_opener = APKOpener(os.path.abspath(path_to_apk))

    @property
    def name(self) -> str:
        """
        Название пакета приложения
        :return: (str) название
        """
        return self._apk.get_application()

    def get_permissions(self) -> List[str]:
        """
        Определяем разрешения приложения из Манифеста
        :return: (list) список разренений
        """
        permissions = list()
        if "uses-permission" in self._manifest:
            for permission in self._manifest["uses-permission"]:
                permissions.append(permission['@android:name'])
        return sorted(permissions)

    def get_flags(self) -> Dict[str, str]:  # TODO Dict.values to bool
        """
        Определяем флаги разные
        возможно, стоит оставить только указанные в задании флаги безопасности
        :return: (dict) пары флаг - значение
        """
        flags = dict()
        meta = list()

        if "application" in self._manifest:
            for k, v in self._manifest["application"].items():
                if k in [
                    "@android:theme", "@android:label", "@android:icon", "@android:name",  # base app resources
                    "activity", "receiver", "service", "provider",  # base A-API instances
                    "activity-alias",
                    "uses-library"
                ]:
                    continue
                if k == "meta-data":
                    meta = v
                    continue
                flags[k.split(":", 1)[1] if ":" in k else k] = v  # ключ не всегда соответствует выражению "@attr:key"

        wv_metrics_disabled = "android.webkit.WebView.MetricsOptOut"
        flags[wv_metrics_disabled] = "false"
        for meta_data in meta:
            if not isinstance(meta_data, OrderedDict):
                continue
            if meta_data["@android:name"] == wv_metrics_disabled:
                flags[wv_metrics_disabled] = meta_data["@android:value"]
                break

        return flags

    def get_codes(self) -> List[str]:
        """
        Определяем коды безопасности
        Я полоагаю, что имеются в виду коды управления приложением через звонки или смс, такие как "#*77771*"
        :return: (list) коды
        """
        code_pattern = re.compile("^[*#][\d*#]*\d[\d*#]*$")
        codes = list(map(lambda string: string.decode(errors="ignore"), self._apk.get_org_strings()))
        codes = list(filter(lambda string: string.startswith(("#", "*")) and code_pattern.match(string), codes))
        return codes

    # А какие библиотеки: xamarin-NET / native-C++ / android-java\kt / cordova-js ?

    def get_libraries_manifest(self) -> List[str]:
        """
        Определяем используемые библиотеки из манифеста,
        а точнее, из опции uses-library, служащей фильтром для GooglePlay
        :return: (list) библиотеки
        """
        libraries = list()
        if "application" in self._manifest:  # use py 3.8 assignment expression := instead of "if = if ="
            app = self._manifest["application"]
            if "uses-library" in app:
                libraries.append(app["uses-library"]['@android:name'])
        return libraries

    def get_libraries_packages(self) -> List[str]:
        """
        Определяем используемые библиотеки из структуры *.dex
        :return: (list) библиотеки
        """
        libraries = set()
        for cls in self._apk.get_classes():
            cls = cls.decode(errors="ignore")
            if "$" in cls:
                cls = cls.split("$", 1)[0]
            # libraries.add(cls.rsplit("/", 1)[0])  # more output
            libraries.add(".".join(cls.split("/", 3)[:3]))  # less
        return sorted(libraries)

    def is_use_dcl(self) -> bool:
        """
        Использует ли приложение DexClassLoader
        :return: (bool)
        """
        for bs in self._apk.get_org_strings():
            if b"dalvik/system/DexClassLoader" in bs:
                return True
        return False

    def get_native_libraries(self) -> Set[str]:
        """
        Определяем используемые библиотеки из файлов .so
        :return: (set) библиотеки
        """

        return self.apk_opener.get_native_libs()

    def get_dll_libraries(self) -> Set[str]:
        """
        Определяем используемые библиотеки .dll
        :return: (set) библиотеки
        """

        return self.apk_opener.get_dll_libs()


def main():
    usage = f"Usage: {os.path.basename(__file__)} path_to_apk"
    if len(sys.argv) != 2:
        print(usage)
        sys.exit(2)
    apk_file = sys.argv[1]
    apk_file = os.path.abspath(apk_file)
    if not os.path.exists(apk_file) or not os.path.isfile(apk_file):
        print("File not found.", usage)
        sys.exit(3)
    os.chdir(os.path.dirname(apk_file))

    apk = APKInfo(apk_file)
    print(f"\tApplication name:\t{apk.name}")

    print("\tApplication permissions:")
    for perm in apk.get_permissions():
        print(perm)

    print("\tApplication flags:")
    for k, v in apk.get_flags().items():
        print(f"{k} = {v}")

    print("\tApplication security codes:")
    for code in apk.get_codes():
        print(code)

    print("\tLibraries from manifest:")
    for lib in apk.get_libraries_manifest():
        print(lib)

    print("\tAndroid libraries from packages:")
    for lib in apk.get_libraries_packages():
        print(lib)

    print(f"\tApplication is uses DexClassLoader: {apk.is_use_dcl()}")

    print("\tNative c/c++ libraries:")
    for lib in apk.get_native_libraries():
        print(lib)

    print("\tNET (.dll) libraries:")
    for lib in apk.get_dll_libraries():
        print(lib)


if __name__ == "__main__":
    main()
