"""
Весьма надуманный тест с распараллеливанием задачи анализа многих APK
"""
import os
import multiprocessing as mp

from apk_analyze import APKInfo, APKOpener

PATH_WITH_APK = "apk_for_tests"


def test(tasks_queue: mp.JoinableQueue, result_queue: mp.Queue):
    while not tasks_queue.empty():
        result = list()
        task = tasks_queue.get()

        # modified code from readme.md
        apk_info = APKInfo(task)
        for field in sorted(
                [getattr(apk_info, m) for m in dir(apk_info) if not m.startswith("_")],
                key=lambda x: callable(x)):
            result.append(
                f"{field.__name__:25}: {field()}" if callable(field) else
                str(field) if not isinstance(field, APKOpener) else
                os.path.basename(task))  # подменим первое поле на имя пакета

        result_queue.put(result)
        tasks_queue.task_done()


def tests():
    result_queue = mp.Queue()
    tasks_queue = mp.JoinableQueue()

    for _ in range(4):  # mp.cpu_count()
        task = mp.Process(target=test, args=(tasks_queue, result_queue))
        task.start()

    for file in os.listdir(PATH_WITH_APK):
        tasks_queue.put(os.path.join(PATH_WITH_APK, file))
    tasks_queue.join()

    while not result_queue.empty():
        print("\n".join(result_queue.get()), end="\n\n")


if __name__ == "__main__":
    tests()
