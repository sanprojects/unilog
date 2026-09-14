"""Run: python3 examples/python/app.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

import unilog.auto
import logging

logging.info("Subscription updated")
logging.error("User not found", {"id": 123})
raise RuntimeError("unhandled — watch this become a FATAL record, then crash normally")
