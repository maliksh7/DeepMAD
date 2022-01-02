
from rich import print
from rich.padding import Padding

test = Padding("[bold black]Hello[/]", (2, 4), style="on cyan",
               expand=True)
print(test)
