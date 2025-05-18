import logging


def setup_logger(log_file="http_detector.log"):
    """Set up logging configuration.

    Args:
        log_file (str): Path to the log file (default: 'http_detector.log')

    Returns:
        logging.Logger: Configured logger instance
    """
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger("http_vulnerability_detector")