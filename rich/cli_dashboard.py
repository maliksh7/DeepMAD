"""
Demonstrates a Rich "application" using the Layout and Live classes.
"""

from time import sleep
from rich.live import Live
from datetime import datetime

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

console = Console()


def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=7),
    )
    layout["main"].split_row(
        Layout(name="side"),
        Layout(name="body", ratio=2, minimum_size=60),
    )
    layout["side"].split(Layout(name="box1"), Layout(name="box2"))
    return layout


def make_sponsor_message() -> Panel:
    """Some example content."""
    sponsor_message = Table.grid(padding=1)
    sponsor_message.add_column(style="green", justify="right")
    sponsor_message.add_column(no_wrap=True)
    sponsor_message.add_row(
        "Sponsor me",
        "[u blue link=https://github.com/sponsors/willmcgugan]https://github.com/sponsors/willmcgugan",
    )
    sponsor_message.add_row(
        "Buy me a :coffee:",
        "[u blue link=https://ko-fi.com/willmcgugan]https://ko-fi.com/willmcgugan",
    )
    sponsor_message.add_row(
        "Twitter",
        "[u blue link=https://twitter.com/willmcgugan]https://twitter.com/willmcgugan",
    )
    sponsor_message.add_row(
        "Blog", "[u blue link=https://www.willmcgugan.com]https://www.willmcgugan.com"
    )

    intro_message = Text.from_markup(
        """Consider supporting my work via Github Sponsors (ask your company / organization), or buy me a coffee to say thanks. - Will McGugan"""
    )

    message = Table.grid(padding=1)
    message.add_column()
    message.add_column(no_wrap=True)
    message.add_row(intro_message, sponsor_message)

    message_panel = Panel(
        Align.center(
            Group(intro_message, "\n", Align.center(sponsor_message)),
            vertical="middle",
        ),
        box=box.ROUNDED,
        padding=(1, 2),
        title="[b red]Wellcome to DeepMAD",
        border_style="bright_blue",
    )
    return message_panel


class Header:
    """Display header with clock."""

    def __rich__(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            "[b]DeepMAD[/b] Application",
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid, style="white on blue")


def make_syntax() -> Syntax:
    code = """\
from flowmeter import Flowmeter

feature_gen = Flowmeter(
    offline = "input.pcap",
    outfunc = None,
    outfile = "output.csv")

feature_gen.run()
    """
    syntax = Syntax(code, "python", line_numbers=True)
    return syntax


job_progress = Progress(
    "{task.description}",
    SpinnerColumn(),
    BarColumn(),
    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
)
job_progress.add_task("[green]Analyzing Network Activity", total=10)
job_progress.add_task("[magenta]Predicting Network Activity", total=40)
job_progress.add_task("[cyan]Preparing Network Activity", total=70)

total = sum(task.total for task in job_progress.tasks)
overall_progress = Progress()
overall_task = overall_progress.add_task("All Jobs", total=int(total))

progress_table = Table.grid(expand=True)
progress_table.add_row(
    Panel(
        overall_progress,
        title="Overall Progress",
        border_style="green",
        padding=(2, 2),
    ),
    Panel(job_progress, title="[b]Tasks", border_style="red", padding=(1, 2)),
)


layout = make_layout()
layout["header"].update(Header())
layout["body"].update(make_sponsor_message())
layout["box2"].update(Panel(make_syntax(), border_style="green"))
layout["box1"].update(Panel(layout.tree, border_style="red"))
layout["footer"].update(progress_table)


with Live(layout, refresh_per_second=4, screen=True):
    while not overall_progress.finished:
        sleep(0.1)
        for job in job_progress.tasks:
            if not job.finished:
                job_progress.advance(job.id)

        completed = sum(task.completed for task in job_progress.tasks)
        overall_progress.update(overall_task, completed=completed)
