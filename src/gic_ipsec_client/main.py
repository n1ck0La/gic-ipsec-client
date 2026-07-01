from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv
    try:
        from PySide6.QtWidgets import QApplication

        from gic_ipsec_client.gui.main_window import MainWindow
    except ImportError as exc:
        print(
            "PySide6 is required for the GIC desktop GUI. "
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
