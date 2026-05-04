# debug.py（プロジェクト直下）
DEBUG = True

def debug_print(*args):
    if DEBUG:
        print("DEBUG:", *args)