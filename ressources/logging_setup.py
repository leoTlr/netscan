import logging
from sys import stdout

# logging is used everywhere instead of print-statements
# normal output is on loglevel INFO
# normal output shall not have [INFO] prefix, other loglevels shall have prefix
#  -> custom formatter
class infoWithoutLevelPrefixFormatter(logging.Formatter):
    """ different log formatting for loglevel INFO """
    def format(self, record):
        if record.levelno != logging.INFO:
            record.msg = '[{}] {}'.format(record.levelname, record.msg)
        return super().format(record)

# needs to be run before main
# can run after arguent parsing setup
def setup_logging(log_level):

    # create a custom handler, set its formatter to the custom formatter
    stdout_handler = logging.StreamHandler(stdout)
    stdout_handler.setFormatter(infoWithoutLevelPrefixFormatter())

    # configure the logger to use the custom handler (arg as list because it needs to be an iterable)
    logging.basicConfig(level=log_level, handlers=[stdout_handler])