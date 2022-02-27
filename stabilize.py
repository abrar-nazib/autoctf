#!/usr/bin/env python3
from time import sleep
import pyautogui
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("python_version")
args = parser.parse_args()
python_version = args.python_version
if python_version == '2':
    python_version = ""


pyautogui.hotkey("alt", "tab")
sleep(2)
pyautogui.write(
    f"python{python_version} -c 'import pty;pty.spawn(\"/bin/bash\")'")
sleep(1)
pyautogui.press("enter")
sleep(1)
pyautogui.hotkey("ctrl", "z")
sleep(1)
pyautogui.write(
    f"stty raw -echo")
sleep(1)
pyautogui.press("enter")
sleep(1)
pyautogui.write(
    f"fg")
sleep(1)
pyautogui.press("enter")
sleep(1)
pyautogui.write("reset")
sleep(1)
pyautogui.press("enter")
