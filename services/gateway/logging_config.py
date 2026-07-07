"""Structured JSON logging (ARCHITECTURE.md §7, ROADMAP item 13).

One configuration for everything that logs: structlog loggers and foreign stdlib
records (uvicorn, sqlalchemy, ...) both land on the root handler and render as the
same JSON shape, shippable to any log aggregator. JSON always — no dev console
renderer; one code path. Decision lines carry the session id as their correlation id,
bound per-session in the Interceptor (pump tasks aren't request-scoped, so contextvars
bound in the HTTP request would never reach them).
"""

import logging

import structlog

_shared_processors: list[structlog.typing.Processor] = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
]


def configure() -> None:
    structlog.configure(
        processors=[
            *_shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    handler = logging.StreamHandler()
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            foreign_pre_chain=_shared_processors,
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    # Uvicorn installs its own plaintext handlers before the app imports; route its
    # records through the root JSON handler instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
