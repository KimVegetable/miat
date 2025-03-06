import logging

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s:%(levelname)s:%(message)s')

def log_message(message):
    logging.debug(message)