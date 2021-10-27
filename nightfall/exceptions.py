class NightfallError(Exception):
    def __init__(self, message, error_code):
        super().__init__(message)
        self.message = message
        self.error_code = error_code

    def __str__(self):
        return f"{str(self.error_code)}: {self.message}"


class NightfallUserError(NightfallError):
    pass


class NightfallSystemError(NightfallError):
    pass
