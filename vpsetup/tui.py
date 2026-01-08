import curses
import os
import random
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


class CursesUI:
    """Tiny curses UI toolkit with menus, inputs, and dialogs."""

    def __init__(self, stdscr: "curses._CursesWindow") -> None:
        self.stdscr = stdscr
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        self.color_title = curses.color_pair(1) | curses.A_BOLD
        self.color_hint = curses.color_pair(2)
        self.color_ok = curses.color_pair(3)
        self.color_err = curses.color_pair(4) | curses.A_BOLD

    def _clear(self) -> None:
        self.stdscr.erase()
        self.stdscr.refresh()

    def msgbox(self, title: str, msg: str) -> None:
        """Shows a blocking message box."""
        self._draw_box(title, msg.splitlines(), footer="Press any key")
        self.stdscr.getch()

    def yesno(self, title: str, msg: str) -> bool:
        """Yes/No dialog."""
        lines = msg.splitlines()
        idx = 0  # 0 yes, 1 no
        while True:
            footer = "[ Yes ]   No" if idx == 0 else "  Yes   [ No ]"
            self._draw_box(title, lines, footer=footer)
            ch = self.stdscr.getch()
            if ch in (curses.KEY_LEFT, ord('h')):
                idx = 0
            elif ch in (curses.KEY_RIGHT, ord('l')):
                idx = 1
            elif ch in (10, 13, curses.KEY_ENTER):
                return idx == 0
            elif ch in (27,):  # ESC
                return False

    def inputbox(self, title: str, prompt: str, default: str, validator: Optional[Callable[[str], Optional[str]]] = None) -> str:
        """Text input box with optional validation."""
        buf = list(default)
        pos = len(buf)
        curses.curs_set(1)
        try:
            while True:
                self._draw_box(title, [prompt, "", "".join(buf)], footer="Enter=OK  ESC=Cancel")
                y, x = self._input_coords(prompt_lines=3)
                self.stdscr.move(y, x + pos)
                ch = self.stdscr.getch()
                if ch in (27,):  # ESC
                    return default
                if ch in (10, 13, curses.KEY_ENTER):
                    val = "".join(buf).strip()
                    if validator:
                        err = validator(val)
                        if err:
                            self.msgbox("Validation", err)
                            continue
                    return val
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if pos > 0:
                        buf.pop(pos - 1)
                        pos -= 1
                elif ch == curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                elif ch == curses.KEY_RIGHT:
                    pos = min(len(buf), pos + 1)
                elif 32 <= ch <= 126:
                    buf.insert(pos, chr(ch))
                    pos += 1
        finally:
            curses.curs_set(0)

    def menu(self, title: str, prompt: str, items: List[Tuple[str, str]]) -> str:
        """Simple vertical menu; returns chosen key."""
        idx = 0
        while True:
            self._clear()
            h, w = self.stdscr.getmaxyx()
            self.stdscr.addstr(1, 2, title, self.color_title)
            self.stdscr.addstr(3, 2, prompt, self.color_hint)
            start_y = 5
            for i, (k, label) in enumerate(items):
                marker = "➤ " if i == idx else "  "
                style = curses.A_REVERSE if i == idx else curses.A_NORMAL
                self.stdscr.addstr(start_y + i, 4, f"{marker}{label}", style)
            self.stdscr.addstr(h - 2, 2, "↑/↓ move   Enter select   ESC cancel", self.color_hint)
            self.stdscr.refresh()

            ch = self.stdscr.getch()
            if ch in (curses.KEY_UP, ord('k')):
                idx = (idx - 1) % len(items)
            elif ch in (curses.KEY_DOWN, ord('j')):
                idx = (idx + 1) % len(items)
            elif ch in (10, 13, curses.KEY_ENTER):
                return items[idx][0]
            elif ch in (27,):
                return items[0][0]

    def _draw_box(self, title: str, lines: List[str], footer: str) -> None:
        self._clear()
        h, w = self.stdscr.getmaxyx()
        box_w = min(90, w - 4)
        box_h = min(max(10, len(lines) + 7), h - 4)
        top = (h - box_h) // 2
        left = (w - box_w) // 2

        win = curses.newwin(box_h, box_w, top, left)
        win.box()
        win.addstr(0, 2, f" {title} ", self.color_title)

        y = 2
        for line in lines[: box_h - 5]:
            win.addstr(y, 2, line[: box_w - 4])
            y += 1

        win.addstr(box_h - 2, 2, footer[: box_w - 4], self.color_hint)
        win.refresh()

    def _input_coords(self, prompt_lines: int) -> Tuple[int, int]:
        h, w = self.stdscr.getmaxyx()
        box_w = min(90, w - 4)
        box_h = min(max(10, prompt_lines + 7), h - 4)
        top = (h - box_h) // 2
        left = (w - box_w) // 2
        # Input line is third content line inside the box (after prompt + blank).
        y = top + 2 + 2
        x = left + 2
        return y, x
