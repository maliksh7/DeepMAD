# Step 1: Import packages and set the working directory

from rich import console
from rich.console import Console
# from rich.color import Color
# from rich import inspect
from rich import print
import subprocess as sub
from rich.panel import Panel
from rich.progress import track
import time
from pyfiglet import Figlet
import shutil

f = Figlet(font='diamond')


def DrawText(text, center=True):
    if center:
        print(*[x.center(shutil.get_terminal_size().columns)
              for x in f.renderText(text).split("\n")], sep="\n")
    else:
        print(f.renderText(text))


DrawText('DeepMAD', center=True)

print("Version 0.1\n\n\n")
