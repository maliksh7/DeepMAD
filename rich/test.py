
from rich import console
from rich.console import Console
# from rich.color import Color
# from rich import inspect
from rich import print
import subprocess as sub
from rich.panel import Panel
from rich.progress import track
import time
import pyfiglet
from rich.theme import Theme

ct = Theme({
    'good': "bold green ",
    'bad': "red underline",
})
rc = Console(theme=ct)

# print("[italic red]Hello[/italic red] World!", locals())

# from rich import pretty
# pretty.install()


# print("Rich and pretty", False)

# Panel.fit("[bold yellow]Hi, I'm a Panel", border_style="red")


# i = 0
# while i < 15:
# print("Hello World! {}".format(i))
# print(Panel.fit(
#     "[bold yellow][*-*] Hi, its a Milgnant Node [*-*]", border_style="red"))
# print(["*_*"])
# print(["Rich and pretty"])


# # color = Color.parse("green")
# # color = Color.from_rgb(red, 30.2, 1.30)
# # inspect(color, methods=True)

# # i += 1
# console = Console()
# console.print("Hello World !!!", style="bold red on white")

# f = Figlet(font='slant')
# print f.renderText('text to render')
# from pyfiglet import Figlet
# f = Figlet(font='c_ascii_')
# print(f.renderText('deepMAD'))
# <div class="open_grepper_editor" title="Edit & Save To Grepper"></div>

# import pyfiglet module

result = pyfiglet.figlet_format("DeepMAD", font="diamond")
print(result)
print("Version 0.1")

# Step 1: Import packages and set the working directory


for file in track(range(5), description="Capturing..."):
    # file = 0
    # while(file < 2):
    print(f"Captured File {file}")

    # file += 1

    time.sleep(0.5)

    file_name = file + 1

    print(
        "\n[bold yellow][*-*] - Dumping file{} as data{}.pcap - [*-*]\n".format(file_name, file_name))

    print(
        "\n[bold blue]<--------------------File {}------------------------>\n".format(file_name))

    p = sub.Popen(('dumpcap', '-i', 'wlp1s0',  '-a', 'filesize:600',
                   '-w', 'pcapF/data{}.pcap'.format(file_name)), stdout=sub.PIPE)
    for row in iter(p.stdout.readline, b''):
        print(row.rstrip())   # process here

    print(
        "\n[green][ DONE ]- Saved pcap file as data{}.pcap[/]\n".format(file_name))

    # print(f"Captured File {file_name}")

    # # file += 1

    # time.sleep(0.5)
