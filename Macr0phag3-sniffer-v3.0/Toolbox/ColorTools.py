#encoding: utf8
from termcolor import colored
import re
import sys

def putColor(text, color):
    return colored(text, color = color, attrs = ['bold'])

def Eraser(text):
    return re.sub(r'\[[0-9]*m', '', text)

def ClearLine(): sys.stdout.flush()










