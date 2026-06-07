"""Board RBAC demo fixture for Coreline Auth self-tests.

Importing the package itself must stay side-effect free. The runnable ASGI app
is created by ``demos.board_rbac.app`` for the uvicorn entrypoint.
"""

__all__ = ["create_app"]


def __getattr__(name: str):
    if name == "create_app":
        from .app import create_app

        return create_app
    raise AttributeError(name)
