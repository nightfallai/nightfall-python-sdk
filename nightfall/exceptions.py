"""
nightfall.exceptions
~~~~~~~~~~~~~~~~~~~~

    This module provides some classes that subclass Exception to provide
    some useful exceptions for the API wrapper.
"""


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class InputError(Error):
    """Exception raised for errors in the input.

    :param id: input id in which the error occurred
    :param message: explanation of the error
    """
    def __init__(self, id, message):
        self.id = id
        self.message = message
