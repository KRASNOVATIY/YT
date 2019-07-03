"""
Заготовка сервиса:
1) переделать в соответствии с MVP
2) сделать вызовы неблокирующими
3) результаты сдалать колапсируемыми
4) вывод сделать последовательным
и много ещё чего
"""

import os

import tornado
import tornado.escape
import tornado.ioloop
import tornado.log
import tornado.web
from tornado.gen import coroutine, Return
from tornado.options import define, options, parse_command_line

from apk_analyze import APKInfo


class NotFoundHandler(tornado.web.RequestHandler):

    def data_received(self, chunk):
        pass

    def prepare(self):
        self.set_status(404)
        self.render("404.html")


class BaseHandler(tornado.web.RequestHandler):

    def data_received(self, chunk):
        pass

    def initialize(self):
        self.set_header("Server", "HashIdentifier")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Methods", "GET, POST")


class MainHandler(BaseHandler):

    def __init__(self, *args, **kwargs):
        super(MainHandler, self).__init__(*args, **kwargs)
        self._render = {
            "template_name": "index.html",
            "server": self.request.host,
        }

    @coroutine
    def get(self):
        return self.render(response={}, **self._render)

    @coroutine
    def post(self):
        response = {}
        file_name = self.get_body_argument("file_name")
        try:
            file = self.request.files["file_obj"]
        except KeyError:
            file = list()
        if file and file_name.endswith(".apk"):
            file = file[0]  # not multifile
            file_path = os.path.join("uploads", file["filename"])
            with open(file_path, "wb") as new_file:
                new_file.write(file["body"])
            try:   
                apk_info = APKInfo(file_path)
            except Exception as e:
                response = {"error": "Файл не распознан как пакетный. Ошибка: " + str(e)}
            else:           
                response = {
                    "success": {
                        "Название файла": file_name,
                        "Название приложения": apk_info.name,
                        "Разрешения": apk_info.get_permissions(),
                        "Флаги": [": ".join(i) for i in apk_info.get_flags().items()],
                        "Секретные коды": apk_info.get_codes(),
                        "Библиотеки java/kt": apk_info.get_libraries_packages(),
                        "Нативные библиотеки": apk_info.get_native_libraries(),
                        "DLL библиотеки": apk_info.get_dll_libraries(),
                        "Используется DexClassLoader": apk_info.is_use_dcl()
                        }
                    }
            os.remove(file_path)
        else:
            response = {"error": "Файл должен иметь расширение \".apk\""}

        return self.render(response=response, **self._render)


settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "template_path": os.path.join(os.path.dirname(__file__), "templates"),
    # "debug": True,
}

handlers = [
    (r"/", MainHandler),
]

application = tornado.web.Application(
    handlers,
    default_handler_class=NotFoundHandler,
    **settings
)

define(
    "port",
    default="8888",
    type=int,
    help="the listen port for the web server"
)


def main():
    application.listen(options.port)
    print("Starting HAI Server on localhost on port number 8888 ...")
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()