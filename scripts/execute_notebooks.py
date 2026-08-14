"""Execute every notebook top-to-bottom and retain the rendered outputs."""

from __future__ import annotations

import ast
import base64
import contextlib
import io
import os
from pathlib import Path

import nbformat
from nbclient import NotebookClient


ROOT = Path(__file__).resolve().parents[1]


def execute_in_process(document, path: Path) -> None:
    """Execute cells when a sandbox cannot open the local Jupyter kernel sockets."""

    import matplotlib

    matplotlib.use("Agg")
    namespace: dict[str, object] = {"__name__": "__main__"}
    previous_cwd = Path.cwd()
    os.chdir(ROOT)
    try:
        execution_count = 0
        for cell_index, cell in enumerate(document.cells):
            if cell.cell_type != "code":
                continue
            execution_count += 1
            cell.execution_count = execution_count
            outputs = []
            stdout = io.StringIO()
            stderr = io.StringIO()
            figures: list[str] = []

            plt = namespace.get("plt")
            if plt is not None:
                def capture_show(*args, **kwargs):
                    buffer = io.BytesIO()
                    plt.gcf().savefig(buffer, format="png", dpi=130, bbox_inches="tight")
                    figures.append(base64.b64encode(buffer.getvalue()).decode("ascii"))
                    plt.close(plt.gcf())

                plt.show = capture_show

            module = ast.parse(cell.source, filename=f"{path.name}#cell-{cell_index}", mode="exec")
            result = None
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                if module.body and isinstance(module.body[-1], ast.Expr):
                    expression = ast.Expression(module.body.pop().value)
                    exec(compile(module, f"{path.name}#cell-{cell_index}", "exec"), namespace)
                    result = eval(compile(expression, f"{path.name}#cell-{cell_index}", "eval"), namespace)
                else:
                    exec(compile(module, f"{path.name}#cell-{cell_index}", "exec"), namespace)

            if stdout.getvalue():
                outputs.append(nbformat.v4.new_output("stream", name="stdout", text=stdout.getvalue()))
            if stderr.getvalue():
                outputs.append(nbformat.v4.new_output("stream", name="stderr", text=stderr.getvalue()))
            for encoded in figures:
                outputs.append(nbformat.v4.new_output("display_data", data={"image/png": encoded}, metadata={}))
            if result is not None:
                data = {"text/plain": repr(result)}
                if hasattr(result, "_repr_html_"):
                    data["text/html"] = result._repr_html_()
                outputs.append(nbformat.v4.new_output("execute_result", data=data, metadata={}, execution_count=execution_count))
            cell.outputs = outputs
    finally:
        os.chdir(previous_cwd)


def main() -> None:
    kernel = os.environ.get("GPU_TRUST_KERNEL", "python3")
    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        document = nbformat.read(path, as_version=4)
        if os.environ.get("GPU_TRUST_IN_PROCESS") == "1":
            execute_in_process(document, path)
        else:
            client = NotebookClient(
                document,
                timeout=240,
                kernel_name=kernel,
                resources={"metadata": {"path": str(ROOT)}},
                allow_errors=False,
            )
            client.execute()
        nbformat.write(document, path)
        code_cells = sum(cell.cell_type == "code" for cell in document.cells)
        outputs = sum(len(cell.get("outputs", [])) for cell in document.cells if cell.cell_type == "code")
        print(f"Executed {path.name}: {code_cells} code cells, {outputs} outputs")


if __name__ == "__main__":
    main()
