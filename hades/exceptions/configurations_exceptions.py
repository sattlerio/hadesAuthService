from hades.exceptions.base_exceptions import Error


class ImproperlyConfigured(Error):
    """
    Exception raised when the configuration is not valid.

    Attributes:
        message -- explanation of the error
    """
