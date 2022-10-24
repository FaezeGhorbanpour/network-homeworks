
class TorToarException(Exception):

    def __init__(self, message):
        self.message = message


class TortToarNetException(TorToarException):

    def __init__(self, message):
        super().__init__(message)


class TorToarVerificationFailure(TorToarException):

    def __init__(self, message):
        super().__init__(message)

