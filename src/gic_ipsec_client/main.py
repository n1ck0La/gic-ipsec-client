from __future__ import annotations

import sys

from gic_ipsec_client import __version__


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv
    if len(args) > 1 and args[1] in {"--version", "-V"}:
        print(f"gic-ipsec-client {__version__}")
        return 0
    try:
        from PySide6.QtWidgets import QApplication

        from gic_ipsec_client.gui.main_window import MainWindow
    except ImportError as exc:
        print(
            "PySide6 is required for the GIC IPsec desktop GUI. "
            "Install the project with GUI dependencies first.",
            file=sys.stderr,
        )
        print(str(exc), file=sys.stderr)
        return 1

    app = QApplication(args)
    app.setApplicationName("GIC IPsec Client")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
