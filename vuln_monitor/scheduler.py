# scheduler.py
import schedule
import time
from vuln_monitor.main import run_monitor
import logging

def run_scheduler():
    logger = logging.getLogger("vuln_monitor_scheduler")
    logging.basicConfig(level=logging.INFO)

    logger.info("Starting scheduler...")
    schedule.every(60).minutes.do(lambda: log_and_run(logger, run_monitor))

    while True:
        schedule.run_pending()
        time.sleep(1)

def log_and_run(logger, job):
    try:
        logger.info("Running scheduled job...")
        job()
        logger.info("Scheduled job completed successfully.")
    except Exception as e:
        logger.error(f"Error during scheduled job: {e}", exc_info=True)
