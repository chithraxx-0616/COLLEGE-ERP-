"""utils/display.py — Terminal UI helpers."""

COLORS = {
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "cyan":    "\033[96m",
    "bold":    "\033[1m",
    "reset":   "\033[0m",
}


def print_colored(msg: str, color: str = "reset"):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['reset']}")


def print_banner():
    banner = r"""
  +==============================================================+
  |        SECURE COLLEGE ERP SYSTEM                            |
  |        Python + MySQL                                       |
  |   SQLi Prevention | RBAC | bcrypt Auth | Audit Log         |
  +==============================================================+
"""
    print_colored(banner, "cyan")


def print_menu(title: str, options: list):
    print_colored(f"\n  +--- {title} ---", "bold")
    for i, opt in enumerate(options, 1):
        print(f"  |  {i}. {opt}")
    print_colored("  +" + "-" * 30, "bold")


def print_table(headers: list, rows: list):
    if not rows:
        print_colored("  (no records found)\n", "yellow")
        return
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, key in enumerate(headers):
            col_widths[i] = max(col_widths[i], len(str(row.get(key, ""))))
    sep = "  +" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = "  |" + "|".join(
        f" {h:<{col_widths[i]}} " for i, h in enumerate(headers)
    ) + "|"
    print(sep)
    print_colored(header_row, "bold")
    print(sep)
    for row in rows:
        line = "  |" + "|".join(
            f" {str(row.get(h,'')):<{col_widths[i]}} "
            for i, h in enumerate(headers)
        ) + "|"
        print(line)
    print(sep + "\n")


def safe_input(prompt: str) -> str:
    """Input wrapper that strips whitespace."""
    try:
        return input(f"  {prompt}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""