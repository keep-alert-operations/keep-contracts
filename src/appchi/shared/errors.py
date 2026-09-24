class AppError(Exception):
    def __init__(self, code: str, message: str, status: int = 422, *, fields=None):
        self.code, self.message, self.status, self.fields = code, message, status, fields
        super().__init__(code)


def unavailable(code="dependency_unavailable"):
    return AppError(code, "Required capability is unavailable. Retry after recovery.", 503)
